// Secret read from the environment — never hard-coded.
export const config = {
  apiKey: process.env.PAYMENTS_API_KEY ?? "",
};
