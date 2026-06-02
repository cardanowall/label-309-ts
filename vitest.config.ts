import { defineConfig } from 'vitest/config';

const workspaceExclude = ['**/node_modules/**', '**/dist/**', '**/coverage/**'];

const bucketBaseExclude = [
  ...workspaceExclude,
  '**/*.integration.test.{ts,tsx,mts}',
  '**/*.kat.test.{ts,tsx,mts}',
  '**/*.nxdomain.test.{ts,tsx,mts}',
];

export default defineConfig({
  test: {
    exclude: workspaceExclude,
    projects: [
      {
        test: {
          name: 'kat',
          include: ['**/*.kat.test.{ts,tsx,mts}'],
          exclude: workspaceExclude,
        },
      },
      {
        test: {
          name: 'integration',
          include: ['**/*.integration.test.{ts,tsx,mts}'],
          exclude: workspaceExclude,
          fileParallelism: false,
        },
      },
      {
        test: {
          name: 'nxdomain',
          include: ['**/*.nxdomain.test.{ts,tsx,mts}'],
          exclude: workspaceExclude,
        },
      },
      {
        test: {
          name: 'unit',
          include: ['**/*.test.{ts,tsx,mts}'],
          exclude: bucketBaseExclude,
        },
      },
    ],
  },
});
