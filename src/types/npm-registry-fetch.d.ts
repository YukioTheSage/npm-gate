declare module 'npm-registry-fetch' {
  interface FetchOptions {
    registry?: string;
    timeout?: number;
    retry?: {
      retries?: number;
      factor?: number;
      minTimeout?: number;
      maxTimeout?: number;
    };
    headers?: Record<string, string>;
  }

  interface RegistryFetch {
    (uri: string, options?: FetchOptions): Promise<Buffer>;
    json(uri: string, options?: FetchOptions): Promise<unknown>;
  }

  const registryFetch: RegistryFetch;
  export default registryFetch;
}
