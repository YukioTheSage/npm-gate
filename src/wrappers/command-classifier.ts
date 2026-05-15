import { parsePackageRef } from '../utils/package-ref.js';

export interface ClassifiedCommand {
  command: string;
  installLike: boolean;
  packageRefs: ReturnType<typeof parsePackageRef>[];
  npmArgs: string[];
}

const installLikeCommands = new Set(['install', 'i', 'add', 'ci']);
const optionsWithValues = new Set(['--registry', '--tag', '--prefix', '--workspace', '-w']);

export function classifyNpmCommand(command: string, args: string[]): ClassifiedCommand {
  const packageArgs: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === '--') break;
    if (arg.startsWith('-')) {
      if (optionsWithValues.has(arg)) i += 1;
      continue;
    }
    packageArgs.push(arg);
  }

  return {
    command,
    installLike: installLikeCommands.has(command),
    packageRefs: packageArgs.map(parsePackageRef),
    npmArgs: [command, ...args]
  };
}
