export function withAuth<T extends (...args: unknown[]) => unknown>(handler: T): T {
  return handler;
}

export function checkPermission(role: string) {
  return function <T extends (...args: unknown[]) => unknown>(handler: T): T {
    return handler;
  };
}

export async function getServerSession(): Promise<{ userId: string } | null> {
  return null;
}
