import parseRange from "range-parser";

export interface Env {
  R2_BUCKET: R2Bucket;
  ALLOWED_ORIGINS?: string;
  CACHE_CONTROL?: string;
  PATH_PREFIX?: string;
  INDEX_FILE?: string;
  NOTFOUND_FILE?: string;
  DIRECTORY_LISTING?: boolean;
  ITEMS_PER_PAGE?: number;
  HIDE_HIDDEN_FILES?: boolean;
  DIRECTORY_CACHE_CONTROL?: string;
  LOGGING?: boolean;
  R2_RETRIES?: number;
  DATE_SUFFIX?: number;
}

const units = ["B", "KB", "MB", "GB", "TB"];

type ParsedRange = { offset: number; length: number } | { suffix: number };

function rangeHasLength(
  object: ParsedRange
): object is { offset: number; length: number } {
  return (<{ offset: number; length: number }>object).length !== undefined;
}

function hasBody(object: R2Object | R2ObjectBody): object is R2ObjectBody {
  return (<R2ObjectBody>object).body !== undefined;
}

function hasSuffix(range: ParsedRange): range is { suffix: number } {
  return (<{ suffix: number }>range).suffix !== undefined;
}

function getRangeHeader(range: ParsedRange, fileSize: number): string {
  return `bytes ${hasSuffix(range) ? fileSize - range.suffix : range.offset}-${
    hasSuffix(range) ? fileSize - 1 : range.offset + range.length - 1
  }/${fileSize}`;
}


async function retryAsync<T>(env: Env, fn: () => Promise<T>): Promise<T> {
  const maxAttempts = env.R2_RETRIES || 0;
  let attempts = 0;

  while (maxAttempts == -1 || attempts <= maxAttempts) {
    try {
      return await fn();
    } catch (err) {
      attempts++;
      if (env.LOGGING) console.error(`Attempt ${attempts} failed:`, err);

      if (attempts <= maxAttempts) {
        const delay = Math.min(1000 * Math.pow(2, attempts - 1), 30000);
        await new Promise((resolve) => setTimeout(resolve, delay));
      } else {
        throw err;
      }
    }
  }
  throw new Error("unreachable");
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const allowedMethods = ["GET", "HEAD", "OPTIONS"];
    if (allowedMethods.indexOf(request.method) === -1) {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { allow: allowedMethods.join(", ") },
      });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: { allow: allowedMethods.join(", ") },
      });
    }

    let triedIndex = false;

    let response: Response | undefined;

    const isCachingEnabled = env.CACHE_CONTROL !== "no-store";
    const cache = caches.default;
    if (isCachingEnabled) {
      response = await cache.match(request);
    }

    // Since we produce this result from the request, we don't need to strictly use an R2Range
    let range: ParsedRange | undefined;

    if (!response || !(response.ok || response.status == 304)) {
      if (env.LOGGING) {
        console.warn("Cache MISS for", request.url);
      }
      const url = new URL(request.url);
      const keyringFilename = "secureblue-keyring.gpg";
      const isoDownloadPath = "/download";
      const checksumDownloadPath = "/downloadSHA256SUM";
      let objectName: string | undefined;
      let key: string | undefined = undefined;
      if (url.pathname === isoDownloadPath || url.pathname === checksumDownloadPath) {
        const de = url.searchParams.get("de");
        const nvidia = url.searchParams.get("nvidia");

        if (!de || !nvidia) {
          return new Response("Missing parameters", { status: 400 });
        }

        key = `secureblue-${de}-${nvidia}-hardened-${env.DATE_SUFFIX}.iso`;
        if (url.pathname === checksumDownloadPath) {
          key += "-CHECKSUM";
        }

        objectName = `${key}`;
      } else if (url.pathname.slice(1) === keyringFilename) {
        key = keyringFilename;
        objectName = `${keyringFilename}`;
      } else {
        return new Response("Not Found", { status: 404 });
      }

      let file: R2Object | R2ObjectBody | null | undefined;

      // Range handling
      if (request.method === "GET") {
        const rangeHeader = request.headers.get("range");
        if (rangeHeader) {
          file = await retryAsync(env, () => env.R2_BUCKET.head(objectName as string));
          if (file === null)
            return new Response("File Not Found", { status: 404 });
          const parsedRanges = parseRange(file.size, rangeHeader);
          // R2 only supports 1 range at the moment, reject if there is more than one
          if (
            parsedRanges !== -1 &&
            parsedRanges !== -2 &&
            parsedRanges.length === 1 &&
            parsedRanges.type === "bytes"
          ) {
            let firstRange = parsedRanges[0];
            range =
              file.size === firstRange.end + 1
                ? { suffix: file.size - firstRange.start }
                : {
                    offset: firstRange.start,
                    length: firstRange.end - firstRange.start + 1,
                  };
          } else {
            return new Response("Range Not Satisfiable", { status: 416 });
          }
        }
      }

      // Etag/If-(Not)-Match handling
      // R2 requires that etag checks must not contain quotes, and the S3 spec only allows one etag
      // This silently ignores invalid or weak (W/) headers
      const getHeaderEtag = (header: string | null) =>
        header?.trim().replace(/^['"]|['"]$/g, "");
      const ifMatch = getHeaderEtag(request.headers.get("if-match"));
      const ifNoneMatch = getHeaderEtag(request.headers.get("if-none-match"));

      const ifModifiedSince = Date.parse(
        request.headers.get("if-modified-since") || ""
      );
      const ifUnmodifiedSince = Date.parse(
        request.headers.get("if-unmodified-since") || ""
      );

      const ifRange = request.headers.get("if-range");
      if (range && ifRange && file) {
        const maybeDate = Date.parse(ifRange);

        if (isNaN(maybeDate) || new Date(maybeDate) > file.uploaded) {
          // httpEtag already has quotes, no need to use getHeaderEtag
          if (ifRange.startsWith("W/") || ifRange !== file.httpEtag)
            range = undefined;
        }
      }

      if (ifMatch || ifUnmodifiedSince) {
        file = await retryAsync(env, () =>
          env.R2_BUCKET.get(objectName as string, {
            onlyIf: {
              etagMatches: ifMatch,
              uploadedBefore: ifUnmodifiedSince
                ? new Date(ifUnmodifiedSince)
                : undefined,
            },
            range,
          })
        );

        if (file && !hasBody(file)) {
          return new Response("Precondition Failed", { status: 412 });
        }
      }

      if (ifNoneMatch || ifModifiedSince) {
        // if-none-match overrides if-modified-since completely
        if (ifNoneMatch) {
          file = await retryAsync(env, () =>
            env.R2_BUCKET.get(objectName as string, {
              onlyIf: { etagDoesNotMatch: ifNoneMatch },
              range,
            })
          );
        } else if (ifModifiedSince) {
          file = await retryAsync(env, () =>
            env.R2_BUCKET.get(objectName as string, {
              onlyIf: { uploadedAfter: new Date(ifModifiedSince) },
              range,
            })
          );
        }
        if (file && !hasBody(file)) {
          return new Response(null, { status: 304 });
        }
      }

      file =
        request.method === "HEAD"
          ? await retryAsync(env, () => env.R2_BUCKET.head(objectName as string))
          : file && hasBody(file)
          ? file
          : await retryAsync(env, () => env.R2_BUCKET.get(objectName as string, { range }));

      let notFound: boolean = false;

      if (file === null) {
        if (env.NOTFOUND_FILE && env.NOTFOUND_FILE != "") {
          notFound = true;
          objectName = env.NOTFOUND_FILE;
          file =
            request.method === "HEAD"
              ? await retryAsync(env, () => env.R2_BUCKET.head(objectName as string))
              : await retryAsync(env, () => env.R2_BUCKET.get(objectName as string));
        }

        // if it's still null, either 404 is disabled or that file wasn't found either
        // this isn't an else because then there would have to be two of them
        if (file == null) {
          return new Response("File Not Found", { status: 404 });
        }
      }

      // Content-Length handling
      let body;
      let contentLength = file.size;
      if (hasBody(file) && file.size !== 0) {
        if (range && !notFound) {
          contentLength = rangeHasLength(range) ? range.length : range.suffix;
        }
        let { readable, writable } = new FixedLengthStream(contentLength);
        file.body.pipeTo(writable);
        body = readable;
      }
      response = new Response(body, {
        status: notFound ? 404 : range ? 206 : 200,
        headers: {
          "accept-ranges": "bytes",
          "access-control-allow-origin": env.ALLOWED_ORIGINS || "",

          etag: notFound ? "" : file.httpEtag,
          // if the 404 file has a custom cache control, we respect it
          "cache-control":
            file.httpMetadata?.cacheControl ??
            (notFound ? "" : env.CACHE_CONTROL || ""),
          expires: file.httpMetadata?.cacheExpiry?.toUTCString() ?? "",
          "last-modified": notFound ? "" : file.uploaded.toUTCString(),

          "content-encoding": file.httpMetadata?.contentEncoding ?? "",
          "content-type":
            file.httpMetadata?.contentType ?? "application/octet-stream",
          "content-language": file.httpMetadata?.contentLanguage ?? "",
          "content-disposition": `attachment; filename="${key}"`,
          "content-range":
            range && !notFound ? getRangeHeader(range, file.size) : "",
          "content-length": contentLength.toString(),
        },
      });

      if (request.method === "GET" && !range && isCachingEnabled && !notFound)
        ctx.waitUntil(cache.put(request, response.clone()));
    } else {
      if (env.LOGGING) {
        console.warn("Cache HIT for", request.url);
      }
    }

    return response;
  },
};

function niceBytes(x: number) {
  let l = 0,
    n = parseInt(x.toString(), 10) || 0;

  while (n >= 1000 && ++l) {
    n = n / 1000;
  }

  return n.toFixed(n < 10 && l > 0 ? 1 : 0) + " " + units[l];
}
