import React, { createContext, useContext, useState } from 'react';

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
    if (!email || !password) {
      throw new Error('Please enter both analyst identifier and credentials.');
    }

    const cleanEmail = email.trim().toLowerCase();
    const registeredUsers = JSON.parse(localStorage.getItem('cybertrace_registered_users') || '[]');
    const existing = registeredUsers.find((u) => u.email.toLowerCase() === cleanEmail);

    let loggedUser;
    if (existing) {
      if (existing.password && existing.password !== password) {
        throw new Error('Invalid credentials. Password does not match.');
      }
      loggedUser = { ...existing };
      delete loggedUser.password;
    } else {
      // Auto-derive a display name if not in registry
      const derivedName = cleanEmail.includes('@')
        ? cleanEmail
            .split('@')[0]
            .replace(/[._-]/g, ' ')
            .replace(/\b\w/g, (c) => c.toUpperCase())
        : 'Analyst ' + cleanEmail;

      loggedUser = {
        ...DEFAULT_ANALYST,
        name: cleanEmail === 'analyst@cybertrace.ai' ? DEFAULT_ANALYST.name : derivedName,
        email: cleanEmail,
      };
    }

    localStorage.setItem('cybertrace_auth', 'true');
    localStorage.setItem('cybertrace_user', JSON.stringify(loggedUser));
    setUser(loggedUser);
    setIsAuthenticated(true);
    return loggedUser;
  };

  const signup = ({ name, email, role, clearance, password }) => {
    if (!name || !email || !password) {
      throw new Error('Please provide full name, email, and a secure password.');
    }

    const cleanEmail = email.trim().toLowerCase();
    const registeredUsers = JSON.parse(localStorage.getItem('cybertrace_registered_users') || '[]');

    if (registeredUsers.some((u) => u.email.toLowerCase() === cleanEmail)) {
      throw new Error('An analyst profile with this email address already exists. Please sign in instead.');
    }

    const newUser = {
      name: name.trim(),
      email: cleanEmail,
      role: role || 'Tier-2 SOC Analyst',
      clearance: clearance || 'CLR-L2',
      shift: 'Shift A',
      registeredAt: new Date().toISOString(),
    };

    // Store in registered users directory
    registeredUsers.push({
      ...newUser,
      password: password,
    });
    localStorage.setItem('cybertrace_registered_users', JSON.stringify(registeredUsers));

    // Sign in immediately
    localStorage.setItem('cybertrace_auth', 'true');
    localStorage.setItem('cybertrace_user', JSON.stringify(newUser));
    setUser(newUser);
    setIsAuthenticated(true);
    return newUser;
  };

  const fastTrackLogin = (customName = 'Guest Forensics Analyst', customRole = 'Live Evaluation Analyst') => {
    const guestUser = {
      name: customName,
      email: 'guest.analyst@cybertrace.ai',
      role: customRole,
      shift: 'Shift Live',
      clearance: 'CLR-L2',
      isGuest: true,
    };
    localStorage.setItem('cybertrace_auth', 'true');
    localStorage.setItem('cybertrace_user', JSON.stringify(guestUser));
    setUser(guestUser);
    setIsAuthenticated(true);
    return guestUser;
  };

  const logout = () => {
    localStorage.removeItem('cybertrace_auth');
    localStorage.removeItem('cybertrace_user');
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, signup, fastTrackLogin, logout }}>
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

