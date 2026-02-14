import "fastify";
import { FastifyPluginAsync } from "fastify";

type MultipartLimits = {
  fieldNameSize?: number;
  fieldSize?: number;
  fields?: number;
  fileSize?: number;
  files?: number;
  headerPairs?: number;
  parts?: number;
};

declare module "@fastify/multipart" {
  const fastifyMultipart: FastifyPluginAsync<{
    limits?: MultipartLimits;
  }>;

  export default fastifyMultipart;
}

declare module "fastify" {
  interface FastifyRequest {
    file(options?: { limits?: { fileSize?: number; files?: number } }): Promise<
      | {
          filename: string;
          mimetype: string;
          encoding: string;
          fieldname: string;
          file: NodeJS.ReadableStream;
          fields: Record<string, unknown>;
        }
      | undefined
    >;
  }
}
