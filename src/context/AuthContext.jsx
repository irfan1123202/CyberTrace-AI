import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

const DEFAULT_ANALYST = {
  name: 'S. Kavitha',
  email: 'analyst@cybertrace.ai',
  role: 'Tier-2 SOC Analyst',
  shift: 'Shift A',
  clearance: 'CLR-L2',
};

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('cybertrace_auth') === 'true';
  });
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('cybertrace_user');
    return saved ? JSON.parse(saved) : DEFAULT_ANALYST;
  });

  const login = (email, password) => {
    // Allows logging in with any non-empty input or the default analyst credentials
    if (!email || !password) {
      throw new Error('Please enter both analyst identifier and credentials.');
    }
    const loggedUser = {
      ...DEFAULT_ANALYST,
      email: email.trim(),
    };
    localStorage.setItem('cybertrace_auth', 'true');
    localStorage.setItem('cybertrace_user', JSON.stringify(loggedUser));
    setUser(loggedUser);
    setIsAuthenticated(true);
    return true;
  };

  const logout = () => {
    localStorage.removeItem('cybertrace_auth');
    localStorage.removeItem('cybertrace_user');
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
