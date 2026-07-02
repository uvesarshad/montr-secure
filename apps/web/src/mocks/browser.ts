import { setupWorker } from "msw/browser";
import { handlers } from "./handlers.js";

/**
 * Browser MSW worker. Started once, client-side, from the Providers tree (see
 * components/providers.tsx). Requires public/mockServiceWorker.js (committed).
 * Node/test consumers import { handlers } directly with msw/node's setupServer.
 */
export const worker = setupWorker(...handlers);
