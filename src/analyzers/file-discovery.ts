import fg from 'fast-glob';

export async function discoverDependencyFiles(cwd: string): Promise<string[]> {
  return fg(
    ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'],
    {
      cwd,
      onlyFiles: true,
      dot: true,
      unique: true
    }
  );
}
