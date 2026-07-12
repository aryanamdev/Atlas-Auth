import { beforeEach, describe, expect, it, vi } from 'vitest';
import { jwtUtils, UserRole } from '#utils/jwt.js';
import { createRefreshToken, rotateRefreshToken, validateRefreshTokenRow } from '#services/token.service.js';


vi.mock('#config/db.js', () => {
  const rows: Array<Record<string, unknown>> = [];

  const extractClauseValues = (value: unknown, seen = new WeakSet<object>()): unknown[] => {
    if (value === null || value === undefined) {
      return [];
    }

    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value instanceof Date
    ) {
      return [value];
    }

    if (Array.isArray(value)) {
      return value.flatMap((item) => extractClauseValues(item, seen));
    }

    if (typeof value === 'object') {
      const object = value as Record<string, unknown>;
      if (seen.has(object)) {
        return [];
      }
      seen.add(object);
      return Object.values(object).flatMap((item) => extractClauseValues(item, seen));
    }

    return [];
  };

  const matchesClause = (row: Record<string, unknown>, whereClause: unknown): boolean => {
    const clauseValues = extractClauseValues(whereClause);
    if (clauseValues.length === 0) {
      return true;
    }

    return clauseValues.some((clauseValue) =>
      Object.values(row).some((columnValue) => columnValue === clauseValue)
    );
  };

  const mockDb = {
    insert: () => ({
      values: async (row: Record<string, unknown>) => {
        rows.push({
          revoked: false,
          revokedAt: null,
          replacedBy: null,
          lastUsedAt: null,
          ...row,
        });
        return [row];
      },
    }),
    select: () => ({
      from: () => ({
        where: async (whereClause: unknown) => rows.filter((row) => matchesClause(row, whereClause)),
      }),
    }),
    update: () => ({
      set(values: Record<string, unknown>) {
        return {
          where: async (whereClause: unknown) => {
            rows.forEach((row) => {
              if (matchesClause(row, whereClause)) {
                Object.assign(row, values);
              }
            });
            return [true];
          },
        };
      },
    }),
    delete: () => ({
      where: async (whereClause: unknown) => {
        for (let i = rows.length - 1; i >= 0; i -= 1) {
          if (matchesClause(rows[i], whereClause)) {
            rows.splice(i, 1);
          }
        }
        return [true];
      },
    }),
    transaction: async (fn: (tx: unknown) => Promise<void>) => {
      await fn(mockDb);
    },
  };

  return {
    db: mockDb,
    __rows: rows,
  };
});

describe('refresh token rotation and reuse detection', () => {
  let rows: Array<Record<string, unknown>>;

  beforeEach(async () => {
    const module = (await import('#config/db.js')) as unknown as {
      __rows: Array<Record<string, unknown>>;
    };
    rows = module.__rows;
    rows.length = 0;
  });

  it('rotates a valid refresh token and revokes the old one', async () => {
    const payload = {
      sub: '1',
      role: UserRole.USER,
      emailVerified: true,
    };

    const token = await createRefreshToken(payload, '127.0.0.1', 'agent');
    const decoded = jwtUtils.verifyRefreshToken(token);
    expect(decoded.jti).toBeDefined();
    expect(decoded.fam).toBeDefined();

    const nextToken = await rotateRefreshToken(decoded.jti, payload, '127.0.0.1', 'agent');
    const nextDecoded = jwtUtils.verifyRefreshToken(nextToken);

    console.log('rows after rotate', rows);
    console.log('decoded old', decoded.jti);
    console.log('next decoded', nextDecoded.jti);

    expect(nextDecoded.fam).toBe(decoded.fam);
    expect(nextDecoded.jti).not.toBe(decoded.jti);

    const oldRow = rows.find((row) => row.jti === decoded.jti);
    const newRow = rows.find((row) => row.jti === nextDecoded.jti);

    expect(oldRow).toBeDefined();
    expect(oldRow?.revoked).toBe(true);
    expect(newRow).toBeDefined();
    expect(newRow?.revoked).toBe(false);
  });

  it('revokes the whole token family on reuse of a rotated refresh token', async () => {
    const payload = {
      sub: '2',
      role: UserRole.USER,
      emailVerified: true,
    };

    const token = await createRefreshToken(payload, '127.0.0.1', 'agent');
    const decoded = jwtUtils.verifyRefreshToken(token);
    const rotated = await rotateRefreshToken(decoded.jti, payload, '127.0.0.1', 'agent');
    const rotatedDecoded = jwtUtils.verifyRefreshToken(rotated);

    await expect(rotateRefreshToken(decoded.jti, payload, '127.0.0.1', 'agent')).rejects.toThrow();

    const familyRows = rows.filter((row) => row.familyId === decoded.fam);
    expect(familyRows.every((row) => row.revoked)).toBe(true);

    await expect(validateRefreshTokenRow(rotatedDecoded.jti)).rejects.toThrow();
  });
});
