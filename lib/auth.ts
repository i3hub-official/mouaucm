// lib/auth.ts
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { prisma } from "@/lib/server/prisma";
import {
  verifyPassword,
  protectData,
  generateSearchableHash,
  unprotectData,
} from "@/lib/security/dataProtection";
import { AuditAction, Role } from "@/lib/generated/prisma/enums";

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        identifier: { label: "Matric/Staff ID or Email", type: "text" },
        password: { label: "Password", type: "password" },
      },

      async authorize(credentials, req) {
        if (!credentials?.identifier || !credentials?.password) return null;

        const identifier = credentials.identifier.trim();
        const password = credentials.password;

        try {
          // Determine if identifier is email or ID number
          const isEmail = identifier.includes("@");
          let user = null;

          if (isEmail) {
            // For email login, we need to use search hash to find the encrypted email
            const protectedEmail = await protectData(identifier, "email");
            const emailSearchHash = protectedEmail.searchHash;

            // Find user by email search hash
            user = await prisma.user.findFirst({
              where: {
                email: protectedEmail.encrypted,
              },
              include: {
                student: {
                  select: {
                    id: true,
                    matricNumber: true,
                    department: true,
                    college: true,
                    course: true,
                    firstName: true,
                    lastName: true,
                    otherName: true,
                  },
                },
                teacher: {
                  select: {
                    id: true,
                    employeeId: true, // Changed from teacherId to employeeId
                    department: true,
                    qualification: true,
                    firstName: true,
                    lastName: true,
                  },
                },
                admin: {
                  select: {
                    id: true,
                    employeeId: true, // Changed from adminId to employeeId
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            });
          } else {
            // For matric/staff ID login
            const upperIdentifier = identifier.toUpperCase();
            
            user = await prisma.user.findFirst({
              where: {
                OR: [
                  {
                    student: {
                      matricNumber: upperIdentifier,
                    },
                  },
                  {
                    teacher: {
                      employeeId: upperIdentifier, // Changed from teacherId to employeeId
                    },
                  },
                  {
                    admin: {
                      employeeId: upperIdentifier, // Changed from adminId to employeeId
                    },
                  },
                ],
              },
              include: {
                student: {
                  select: {
                    id: true,
                    matricNumber: true,
                    department: true,
                    college: true,
                    course: true,
                    firstName: true,
                    lastName: true,
                    otherName: true,
                  },
                },
                teacher: {
                  select: {
                    id: true,
                    employeeId: true, // Changed from teacherId to employeeId
                    department: true,
                    qualification: true,
                    firstName: true,
                    lastName: true,
                  },
                },
                admin: {
                  select: {
                    id: true,
                    employeeId: true, // Changed from adminId to employeeId
                    firstName: true,
                    lastName: true,
                  },
                },
              },
            });
          }

          if (!user) {
            await logFailed("not_found", identifier, req);
            return null;
          }

          // Account checks
          if (!user.isActive) {
            await logFailed("inactive", identifier, req, user.id);
            return null;
          }

          if (!user.emailVerified) {
            await logFailed("email_not_verified", identifier, req, user.id);
            return null;
          }

          if (
            user.accountLocked &&
            user.lockedUntil &&
            user.lockedUntil > new Date()
          ) {
            await logFailed("account_locked", identifier, req, user.id);
            return null;
          }

          // Verify password
          const isValidPassword = user.passwordHash
            ? await verifyPassword(password, user.passwordHash)
            : false;

          if (!isValidPassword) {
            await handleFailedLogin(user, identifier, req);
            return null;
          }

          // Reset failed attempts on successful login
          await prisma.user.update({
            where: { id: user.id },
            data: {
              failedLoginAttempts: 0,
              accountLocked: false,
              lockedUntil: null,
              lastLoginAt: new Date(),
              loginCount: { increment: 1 },
            },
          });

          // Decrypt name fields
          let firstName = "";
          let lastName = "";
          let otherName = "";

          if (user.student) {
            firstName = await unprotectData(user.student.firstName, "name");
            lastName = await unprotectData(user.student.lastName, "name");
            otherName = user.student.otherName 
              ? await unprotectData(user.student.otherName, "name") 
              : "";
          } else if (user.teacher) {
            firstName = await unprotectData(user.teacher.firstName, "name");
            lastName = await unprotectData(user.teacher.lastName, "name");
          } else if (user.admin) {
            firstName = await unprotectData(user.admin.firstName, "name");
            lastName = await unprotectData(user.admin.lastName, "name");
          }

          // Format user name based on role
          let userName = "";
          let fullName = "";

          if (user.student) {
            userName = user.student.matricNumber;
            fullName = `${lastName} ${firstName}${otherName ? ` ${otherName}` : ""}`;
          } else if (user.teacher) {
            userName = user.teacher.employeeId; // Changed from teacherId to employeeId
            fullName = `${lastName} ${firstName}`;
          } else if (user.admin) {
            userName = user.admin.employeeId; // Changed from adminId to employeeId
            fullName = `${lastName} ${firstName}`;
          }

          // Create audit log for successful login
          await prisma.auditLog.create({
            data: {
              userId: user.id,
              action: AuditAction.USER_LOGGED_IN,
              resourceType: "USER",
              details: {
                role: user.role,
                identifier,
                loginMethod: "credentials",
              },
              ipAddress: getIp(req),
              userAgent: req?.headers?.["user-agent"] ?? "unknown",
            },
          });

          return {
            id: user.id,
            email: user.email, // This is encrypted, but NextAuth needs it
            name: fullName || userName,
            role: user.role,

            // Student specific
            matricNumber: user.student?.matricNumber ?? null,
            college: user.student?.college ?? null,
            course: user.student?.course ?? null,
            department:
              user.student?.department ?? user.teacher?.department ?? null,

            // Staff specific
            employeeId: user.teacher?.employeeId ?? user.admin?.employeeId ?? null, // Unified field
            qualification: user.teacher?.qualification ?? null,

            // Additional info
            fullName: fullName,
            userName: userName,
          };
        } catch (error) {
          console.error("Auth error:", error);
          await prisma.auditLog.create({
            data: {
              action: AuditAction.AUTH_ERROR,
              resourceType: "USER",
              details: {
                identifier,
                error: error instanceof Error ? error.message : "Unknown",
                stack: error instanceof Error ? error.stack : undefined,
              },
              ipAddress: getIp(req),
              userAgent: req?.headers?.["user-agent"] ?? "unknown",
            },
          });
          return null;
        }
      },
    }),
  ],

  session: {
    strategy: "jwt",
    maxAge: 8 * 60 * 60, // 8 hours
  },

  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role;
        token.matricNumber = user.matricNumber;
        token.employeeId = user.employeeId; // Changed from teacherId to employeeId
        token.department = user.department;
        token.college = user.college;
        token.course = user.course;
        token.qualification = user.qualification;
        token.fullName = user.fullName;
        token.userName = user.userName;
      }
      return token;
    },

    async session({ session, token }) {
      if (token.sub) {
        session.user.id = token.sub;
      }
      session.user.role = token.role as string;
      session.user.matricNumber = token.matricNumber as string | null;
      session.user.employeeId = token.employeeId as string | null; // Changed from teacherId to employeeId
      session.user.department = token.department as string | null;
      session.user.college = token.college as string | null;
      session.user.course = token.course as string | null;
      session.user.qualification = token.qualification as string | null;
      session.user.fullName = token.fullName as string | null;
      session.user.userName = token.userName as string | null;
      return session;
    },

    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url;
      return baseUrl;
    },
  },

  pages: {
    signIn: "/signin",
    signOut: "/signout",
    error: "/auth/error",
  },

  // Security settings
  secret: process.env.NEXTAUTH_SECRET,
  useSecureCookies: process.env.NODE_ENV === "production",
};

// Helper functions
function getIp(req: any): string {
  try {
    return (
      req?.headers?.["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req?.headers?.["x-real-ip"] ||
      req?.socket?.remoteAddress ||
      "unknown"
    );
  } catch {
    return "unknown";
  }
}

async function logFailed(
  reason: string,
  identifier: string,
  req: any,
  userId?: string
) {
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        action: AuditAction.USER_LOGIN_FAILED,
        resourceType: "USER",
        details: {
          identifier,
          reason,
          timestamp: new Date().toISOString(),
        },
        ipAddress: getIp(req),
        userAgent: req?.headers?.["user-agent"] ?? "unknown",
      },
    });
  } catch (error) {
    console.error("Failed to log failed login attempt:", error);
  }
}

async function handleFailedLogin(user: any, identifier: string, req: any) {
  try {
    const attempts = (user.failedLoginAttempts || 0) + 1;
    const lock = attempts >= 5;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: attempts,
        lastFailedLoginAt: new Date(),
        ...(lock && {
          accountLocked: true,
          lockedUntil: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
        }),
      },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: AuditAction.USER_LOGIN_FAILED,
        resourceType: "USER",
        details: {
          identifier,
          reason: "invalid_password",
          attempts,
          locked: lock,
          lockedUntil: lock
            ? new Date(Date.now() + 30 * 60 * 1000).toISOString()
            : undefined,
        },
        ipAddress: getIp(req),
        userAgent: req?.headers?.["user-agent"] ?? "unknown",
      },
    });
  } catch (error) {
    console.error("Failed to handle failed login:", error);
  }
}

// Extend NextAuth types
declare module "next-auth" {
  interface User {
    role: string;
    matricNumber?: string | null;
    employeeId?: string | null; // Changed from teacherId to employeeId (unified)
    department?: string | null;
    college?: string | null;
    course?: string | null;
    qualification?: string | null;
    fullName?: string | null;
    userName?: string | null;
  }

  interface Session {
    user: {
      id: string;
      email?: string | null;
      name?: string | null;
      image?: string | null;
      role: string;
      matricNumber?: string | null;
      employeeId?: string | null; // Changed from teacherId to employeeId
      department?: string | null;
      college?: string | null;
      course?: string | null;
      qualification?: string | null;
      fullName?: string | null;
      userName?: string | null;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    role: string;
    matricNumber?: string | null;
    employeeId?: string | null; // Changed from teacherId to employeeId
    department?: string | null;
    college?: string | null;
    course?: string | null;
    qualification?: string | null;
    fullName?: string | null;
    userName?: string | null;
  }
}