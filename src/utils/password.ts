import argon2 from 'argon2';

const DEFAULT_ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 4,
  parallelism: 1,
};

export const hashPassword = async (password: string): Promise<string> => {
  return argon2.hash(password, DEFAULT_ARGON2_OPTIONS);
};

export const verifyPassword = async (
  hashedPassword: string,
  password: string
): Promise<boolean> => {
  return argon2.verify(hashedPassword, password);
};
