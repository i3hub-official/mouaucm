// File: app/components/t/types.ts
export interface TeacherUser {
  id: string;
  name: string;
  email: string;
  role: "TEACHER" | "LECTURER" | "STUDENT" | "ADMIN";
  isActive: boolean;
  lastLoginAt?: Date;
  profile?: {
    photo?: string | Blob | null; // Made optional with proper union
    firstName: string;
    lastName: string;
    department: string;
    college: string;
    employeeId: string; // Changed from teacherId to employeeId
    academicRank: string;
    passportUrl?: string | null;
    phone?: string | null;
    dateEmployed?: string | null;
  };
}

export interface AuthState {
  user: TeacherUser | null;
  isLoading: boolean;
  error: string | null;
  isAuthenticated: boolean;
}