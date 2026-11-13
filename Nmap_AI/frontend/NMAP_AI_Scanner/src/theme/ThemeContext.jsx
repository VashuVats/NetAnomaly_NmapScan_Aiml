import React, { createContext, useContext, useEffect, useState } from 'react';

// 'system' follows the operating system setting; 'light' and 'dark' are fixed.
const ThemeContext = createContext({ choice: 'system', setChoice: () => {} });
const STORAGE_KEY = 'netscan-theme';

function readChoice() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

function systemPrefersDark() {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches;
}

export function ThemeProvider({ children }) {
  const [choice, setChoiceState] = useState(readChoice);
  const [systemDark, setSystemDark] = useState(systemPrefersDark);

  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!mq) return undefined;
    const onChange = (e) => setSystemDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const resolved = choice === 'system' ? (systemDark ? 'dark' : 'light') : choice;

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  const setChoice = (value) => {
    setChoiceState(value);
    try {
      if (value === 'system') localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, value);
    } catch {
      /* private mode: the choice just will not be remembered */
    }
  };

  return <ThemeContext.Provider value={{ choice, resolved, setChoice }}>{children}</ThemeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export const useTheme = () => useContext(ThemeContext);
