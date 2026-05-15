export class GateError extends Error {
  constructor(
    message: string,
    public readonly exitCode: number
  ) {
    super(message);
    this.name = 'GateError';
  }
}

export class ConfigError extends GateError {
  constructor(message: string) {
    super(message, 3);
    this.name = 'ConfigError';
  }
}
