import { createContext, useContext } from 'react';
import type { Me } from './types';

export const SessionContext = createContext<Me | null>(null);

/** The signed-in admin. Only used below <App>, which waits for it. */
export function useMe(): Me {
  const me = useContext(SessionContext);
  if (!me) throw new Error('useMe outside the session');
  return me;
}
