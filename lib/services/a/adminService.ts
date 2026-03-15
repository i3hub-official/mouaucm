// lib/services/a/adminService.ts
import { prisma } from "@/lib/server/prisma";
import {
  protectData,
  unprotectData,
  verifyPassword,
  validatePasswordStrength,
} from "@/lib/security/dataProtection";
import { AuditAction, ResourceType } from "@/lib/generated/prisma/enums";
import { AdminUser } from "@/lib/types/a/index";

// Define the actual return type from Prisma
type PrismaAdminResult = {
  id: string;
  lastName: string;
  firstname: string;
  othername: string | null;
  gender: string | null;
  email: string;
  phone: string;
  department: string;
  institution: string | null;
  qualification: string | null;
  specialization: string | null;
  experience: string | null;
  dateJoined: Date;
  isActive: boolean;
  passportUrl: string | null;
  userId: string;
  emailSearchHash: string | null;
  phoneSearchHash: string | null;
  employeeIdSearchHash: string | null;
  lastActivityAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  user: {
    id: string;
    email: string;
    name: string | null;
    role: string;
    isActive: boolean;
    emailVerified: Date | null;
    lastLoginAt: Date | null;
    createdAt: Date;
  };
} & {
  employeeId: string; // Add employeeId explicitly
};

export class AdminService {
  /**
   * Get admin by ID
   */
  static async getAdminById(id: string): Promise<AdminUser | null> {
    try {
      const admin = await prisma.admin.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              role: true,
              isActive: true,
              emailVerified: true,
              lastLoginAt: true,
              createdAt: true,
            },
          },
        },
      });

      if (!admin) {
        return null;
      }

      // Since we know employeeId exists in the schema but TypeScript doesn't,
      // we need to access it carefully
      const employeeId = (admin as any).employeeId;
      
      if (!employeeId) {
        console.error("Employee ID not found in admin record");
        return null;
      }

      // Decrypt sensitive data
      const decryptedAdmin: AdminUser = {
        id: admin.id,
        teacherId: employeeId, // Map employeeId to teacherId for the interface
        email: await this.decryptField(admin.user.email, "email"),
        phone: await this.decryptField(admin.phone, "phone"),
        firstName: await this.decryptField(admin.firstName, "name"),
        lastName: await this.decryptField(admin.lastName, "name"),
              otherName: admin.otherName
          ? await this.decryptField(admin.otherName, "name")
          : null,
        gender: (admin.gender as "MALE" | "FEMALE" | "OTHER") ?? "OTHER",
        department: admin.department,
        institution: admin.institution || "",
        qualification: admin.qualification ?? undefined,
        specialization: admin.specialization ?? undefined,
        experience: admin.experience,
        dateJoined: admin.dateJoined,
        isActive: admin.user.isActive,
        passportUrl: admin.passportUrl,
        // Add required properties from user
        role: "ADMIN",
        name: admin.user.name ?? "",
        emailVerified: admin.user.emailVerified,
        lastLoginAt: admin.user.lastLoginAt,
        createdAt: admin.user.createdAt,
        address: null,
      };

      return decryptedAdmin;
    } catch (error) {
      console.error("Error getting admin by ID:", error);
      throw error;
    }
  }

  /**
   * Get admin by user ID
   */
  static async getAdminByUserId(userId: string): Promise<AdminUser | null> {
    try {
      const admin = await prisma.admin.findUnique({
        where: { userId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              role: true,
              isActive: true,
              emailVerified: true,
              lastLoginAt: true,
              createdAt: true,
            },
          },
        },
      });

      if (!admin) {
        return null;
      }

      const employeeId = (admin as any).employeeId;
      
      if (!employeeId) {
        console.error("Employee ID not found in admin record");
        return null;
      }

      // Decrypt sensitive data
      const decryptedAdmin: AdminUser = {
        id: admin.id,
        teacherId: employeeId,
        email: await this.decryptField(admin.user.email, "email"),
        phone: await this.decryptField(admin.phone, "phone"),
        firstName: await this.decryptField(admin.firstName, "name"),
        lastName: await this.decryptField(admin.lastName, "name"),
               otherName: admin.otherName
          ? await this.decryptField(admin.otherName, "name")
          : null,
        gender: (admin.gender as "MALE" | "FEMALE" | "OTHER") ?? "OTHER",
        department: admin.department,
        institution: admin.institution || "",
        qualification: admin.qualification ?? undefined,
        specialization: admin.specialization ?? undefined,
        experience: admin.experience,
        dateJoined: admin.dateJoined,
        isActive: admin.user.isActive,
        passportUrl: admin.passportUrl,
        role: "ADMIN",
        name: admin.user.name ?? "",
        emailVerified: admin.user.emailVerified,
        lastLoginAt: admin.user.lastLoginAt,
        createdAt: admin.user.createdAt,
        address: null,
      };

      return decryptedAdmin;
    } catch (error) {
      console.error("Error getting admin by user ID:", error);
      throw error;
    }
  }

  /**
   * Get admin by email
   */
  static async getAdminByEmail(email: string): Promise<AdminUser | null> {
    try {
      const protectedEmail = await protectData(email, "email");

      const admin = await prisma.admin.findFirst({
        where: {
          emailSearchHash: protectedEmail.searchHash,
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              role: true,
              isActive: true,
              emailVerified: true,
              lastLoginAt: true,
              createdAt: true,
            },
          },
        },
      });

      if (!admin) {
        return null;
      }

      const employeeId = (admin as any).employeeId;
      
      if (!employeeId) {
        console.error("Employee ID not found in admin record");
        return null;
      }

      // Decrypt sensitive data
      const decryptedAdmin: AdminUser = {
        id: admin.id,
        teacherId: employeeId,
        email: await this.decryptField(admin.user.email, "email"),
        phone: await this.decryptField(admin.phone, "phone"),
        firstName: await this.decryptField(admin.firstName, "name"),
        lastName: await this.decryptField(admin.lastName, "name"),
              otherName: admin.otherName
          ? await this.decryptField(admin.otherName, "name")
          : null,
        gender: (admin.gender as "MALE" | "FEMALE" | "OTHER") ?? "OTHER",
        department: admin.department,
        institution: admin.institution || "",
        qualification: admin.qualification ?? undefined,
        specialization: admin.specialization ?? undefined,
        experience: admin.experience,
        dateJoined: admin.dateJoined,
        isActive: admin.user.isActive,
        passportUrl: admin.passportUrl,
        role: "ADMIN",
        name: admin.user.name ?? "",
        emailVerified: admin.user.emailVerified,
        lastLoginAt: admin.user.lastLoginAt,
        createdAt: admin.user.createdAt,
        address: null,
      };

      return decryptedAdmin;
    } catch (error) {
      console.error("Error getting admin by email:", error);
      throw error;
    }
  }

  /**
   * Get admin by employee ID
   */
  static async getAdminByEmployeeId(
    employeeId: string
  ): Promise<AdminUser | null> {
    try {
      const admin = await prisma.admin.findUnique({
        where: { employeeId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              role: true,
              isActive: true,
              emailVerified: true,
              lastLoginAt: true,
              createdAt: true,
            },
          },
        },
      });

      if (!admin) {
        return null;
      }

      // Decrypt sensitive data
      const decryptedAdmin: AdminUser = {
        id: admin.id,
        teacherId: admin.employeeId, // This works because we're querying by employeeId
        email: await this.decryptField(admin.user.email, "email"),
        phone: await this.decryptField(admin.phone, "phone"),
        firstName: await this.decryptField(admin.firstName, "name"),
               lastName: await this.decryptField(admin.lastName, "name"),
        otherName: admin.otherName
          ? await this.decryptField(admin.otherName, "name")
          : null,
        gender: (admin.gender as "MALE" | "FEMALE" | "OTHER") ?? "OTHER",
        department: admin.department,
        institution: admin.institution || "",
        qualification: admin.qualification ?? undefined,
        specialization: admin.specialization ?? undefined,
        experience: admin.experience,
        dateJoined: admin.dateJoined,
        isActive: admin.user.isActive,
        passportUrl: admin.passportUrl,
        role: "ADMIN",
        name: admin.user.name ?? "",
        emailVerified: admin.user.emailVerified,
        lastLoginAt: admin.user.lastLoginAt,
        createdAt: admin.user.createdAt,
        address: null,
      };

      return decryptedAdmin;
    } catch (error) {
      console.error("Error getting admin by employee ID:", error);
      throw error;
    }
  }

  /**
   * Create admin
   */
  static async createAdmin(adminData: {
    employeeId: string;
    firstName: string;
    lastName: string;
    otherName?: string;
    gender?: string;
    email: string;
    phone: string;
    department: string;
    institution?: string;
    qualification?: string;
    specialization?: string;
    experience?: string;
    password: string;
  }) {
    try {
      // Check if email already exists
      const protectedEmail = await protectData(adminData.email, "email");
      const existingUser = await prisma.user.findFirst({
        where: {
          email: protectedEmail.encrypted,
        },
      });

      if (existingUser) {
        throw new Error("A user with this email already exists");
      }

      // Check if employee ID already exists
      const existingAdmin = await prisma.admin.findFirst({
        where: { employeeId: adminData.employeeId },
      });

      if (existingAdmin) {
        throw new Error("An admin with this employee ID already exists");
      }

      // Validate password strength
      const passwordValidation = validatePasswordStrength(adminData.password);
      if (!passwordValidation.isValid) {
        throw new Error(
          `Password validation failed: ${passwordValidation.errors.join(", ")}`
        );
      }

      // Hash the password
      const hashedPassword = await protectData(adminData.password, "password");

      // Create user account
      const user = await prisma.user.create({
        data: {
          email: protectedEmail.encrypted,
          passwordHash: hashedPassword.encrypted,
          role: "ADMIN",
          isActive: false,
          emailVerified: null,
          name: `${adminData.firstName} ${adminData.lastName}`,
        },
      });

      // Create admin profile
      const admin = await prisma.admin.create({
        data: {
          userId: user.id,
          employeeId: adminData.employeeId,
          firstName: (await protectData(adminData.firstName, "name")).encrypted,
          lastName: (await protectData(adminData.lastName, "name")).encrypted,
          otherName: adminData.otherName
            ? (
                await protectData(adminData.otherName, "name")
              ).encrypted
            : null,
          gender: adminData.gender
            ? (adminData.gender.toUpperCase() as "MALE" | "FEMALE" | "OTHER")
            : undefined,
          email: protectedEmail.encrypted,
          phone: (await protectData(adminData.phone, "phone")).encrypted,
          department: adminData.department,
          institution: adminData.institution,
          qualification: adminData.qualification,
          specialization: adminData.specialization,
          experience: adminData.experience,
          dateJoined: new Date(),
          isActive: true,
          emailSearchHash: protectedEmail.searchHash,
          phoneSearchHash: (
            await protectData(adminData.phone, "phone")
          ).searchHash,
          employeeIdSearchHash: (
            await protectData(adminData.employeeId, "name")
          ).searchHash,
        },
      });

      // Log admin creation
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: AuditAction.ADMIN_REGISTERED,
          resourceType: ResourceType.ADMIN,
          resourceId: admin.id,
          details: {
            employeeId: adminData.employeeId,
            email: protectedEmail.encrypted,
            department: adminData.department,
            institution: adminData.institution,
          },
        },
      });

      console.log(`Admin account created for: ${adminData.email}`);

      return {
        success: true,
        admin: {
          id: admin.id,
          userId: user.id,
          email: adminData.email,
          lastName: adminData.lastName,
          firstname: adminData.firstName,
          otherName: adminData.otherName,
          gender: adminData.gender,
          phone: adminData.phone,
          department: adminData.department,
          institution: adminData.institution,
          qualification: adminData.qualification,
          specialization: adminData.specialization,
          experience: adminData.experience,
          dateJoined: admin.dateJoined,
          isActive: true,
        },
        message:
          "Admin account created successfully. Please check your email for verification.",
      };
    } catch (error) {
      console.error("Error creating admin:", error);
      throw error;
    }
  }

  /**
   * Update admin profile
   */
  static async updateAdminProfile(
    adminId: string,
    profileData: {
      firstName?: string;
      lastName?: string;
      otherName?: string;
      gender?: string;
      phone?: string;
      department?: string;
      institution?: string;
      qualification?: string;
      specialization?: string;
      experience?: string;
      passportUrl?: string;
    }
  ) {
    try {
      const admin = await prisma.admin.findUnique({
        where: { id: adminId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      if (!admin) {
        throw new Error("Admin not found");
      }

      const updateData: any = {};

      if (profileData.firstName !== undefined) {
        updateData.firstName = (await protectData(profileData.firstName, "name")).encrypted;
      }
      if (profileData.lastName !== undefined) {
        updateData.lastName = (await protectData(profileData.lastName, "name")).encrypted;
      }
      if (profileData.otherName !== undefined) {
        updateData.otherName = (await protectData(profileData.otherName, "name")).encrypted;
      }
      if (profileData.gender !== undefined) {
        updateData.gender = profileData.gender.toUpperCase() as "MALE" | "FEMALE" | "OTHER";
      }
      if (profileData.phone !== undefined) {
        const protectedPhone = await protectData(profileData.phone, "phone");
        updateData.phone = protectedPhone.encrypted;
        updateData.phoneSearchHash = protectedPhone.searchHash;
      }
      if (profileData.department !== undefined) {
        updateData.department = profileData.department;
      }
      if (profileData.institution !== undefined) {
        updateData.institution = profileData.institution;
      }
      if (profileData.qualification !== undefined) {
        updateData.qualification = profileData.qualification;
      }
      if (profileData.specialization !== undefined) {
        updateData.specialization = profileData.specialization;
      }
      if (profileData.experience !== undefined) {
        updateData.experience = profileData.experience;
      }
      if (profileData.passportUrl !== undefined) {
        updateData.passportUrl = profileData.passportUrl;
      }

      await prisma.admin.update({
        where: { id: adminId },
        data: {
          ...updateData,
          updatedAt: new Date(),
        },
      });

      await prisma.auditLog.create({
        data: {
          userId: admin.userId,
          action: AuditAction.PROFILE_UPDATED,
          resourceType: ResourceType.ADMIN,
          resourceId: adminId,
          details: {
            updatedFields: Object.keys(profileData),
          },
        },
      });

      return {
        success: true,
        message: "Admin profile updated successfully",
      };
    } catch (error) {
      console.error("Error updating admin profile:", error);
      throw error;
    }
  }

  /**
   * Authenticate admin
   */
  static async authenticateAdmin(
    email: string,
    password: string
  ): Promise<AdminUser> {
    try {
      const protectedEmail = await protectData(email, "email");

      const admin = await prisma.admin.findFirst({
        where: {
          emailSearchHash: protectedEmail.searchHash,
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              passwordHash: true,
              isActive: true,
              emailVerified: true,
              lastLoginAt: true,
              createdAt: true,
              role: true,
              accountLocked: true,
              lockedUntil: true,
              failedLoginAttempts: true,
              lastFailedLoginAt: true,
            },
          },
        },
      });

      if (!admin) {
        throw new Error("Invalid email or password");
      }

      const employeeId = (admin as any).employeeId;
      
      if (!employeeId) {
        throw new Error("Invalid admin record");
      }

      if (
        admin.user.accountLocked &&
        admin.user.lockedUntil &&
        admin.user.lockedUntil > new Date()
      ) {
        throw new Error(
          "Account is temporarily locked. Please try again later."
        );
      }

      if (!admin.user.passwordHash) {
        throw new Error("Invalid email or password");
      }
      const isValidPassword = await verifyPassword(
        password,
        admin.user.passwordHash
      );

      if (!isValidPassword) {
        const failedAttempts = admin.user.failedLoginAttempts + 1;
        const updateData: any = {
          failedLoginAttempts: failedAttempts,
          lastFailedLoginAt: new Date(),
        };

        if (failedAttempts >= 5) {
          updateData.accountLocked = true;
          updateData.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        }

        await prisma.user.update({
          where: { id: admin.user.id },
          data: updateData,
        });

        throw new Error("Invalid email or password");
      }

      if (admin.user.failedLoginAttempts > 0) {
        await prisma.user.update({
          where: { id: admin.user.id },
          data: {
            failedLoginAttempts: 0,
            lastFailedLoginAt: null,
            accountLocked: false,
            lockedUntil: null,
          },
        });
      }

      await prisma.user.update({
        where: { id: admin.user.id },
        data: {
          lastLoginAt: new Date(),
          loginCount: { increment: 1 },
        },
      });

      await prisma.auditLog.create({
        data: {
          userId: admin.user.id,
          action: AuditAction.USER_LOGGED_IN,
          resourceType: ResourceType.ADMIN,
          resourceId: admin.id,
          details: {
            email: protectedEmail.encrypted,
            role: "ADMIN",
          },
        },
      });

      const decryptedAdmin: AdminUser = {
        id: admin.id,
        teacherId: employeeId,
        email: await this.decryptField(admin.user.email, "email"),
        phone: await this.decryptField(admin.phone, "phone"),
        firstName: await this.decryptField(admin.firstName, "name"),
        lastName: await this.decryptField(admin.lastName, "name"),
        otherName: await this.decryptField(admin.otherName || "", "name"),
        gender: (admin.gender as "MALE" | "FEMALE" | "OTHER") ?? "OTHER",
        department: admin.department,
        institution: admin.institution || "",
        qualification: admin.qualification ?? undefined,
        specialization: admin.specialization ?? undefined,
        experience: admin.experience,
        dateJoined: admin.dateJoined,
        isActive: admin.user.isActive,
        passportUrl: admin.passportUrl,
        role: "ADMIN",
        name: admin.user.name ?? "",
        emailVerified: admin.user.emailVerified,
        lastLoginAt: admin.user.lastLoginAt,
        createdAt: admin.user.createdAt,
        address: null,
      };

      return decryptedAdmin;
    } catch (error) {
      console.error("Admin authentication error:", error);
      throw error;
    }
  }

  /**
   * Get all admins with pagination
   */
  static async getAllAdmins(
    page: number = 1,
    limit: number = 10,
    filters?: {
      department?: string;
      isActive?: boolean;
    }
  ) {
    try {
      const skip = (page - 1) * limit;

      const where: any = {};
      if (filters?.department) {
        where.department = filters.department;
      }
      if (filters?.isActive !== undefined) {
        where.user = {
          isActive: filters.isActive,
        };
      }

      const [admins, total] = await Promise.all([
        prisma.admin.findMany({
          where,
          skip,
          take: limit,
          include: {
            user: {
              select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isActive: true,
                emailVerified: true,
                lastLoginAt: true,
                createdAt: true,
              },
            },
          },
        }),
        prisma.admin.count({ where }),
      ]);

      // Process each admin to extract employeeId
      const decryptedAdmins = await Promise.all(
        admins.map(async (admin) => {
          const employeeId = (admin as any).employeeId;
          
          return {
            id: admin.id,
            employeeId: employeeId || "",
            firstName: await this.decryptField(admin.firstName, "name"),
            lastName: await this.decryptField(admin.lastName, "name"),
            otherName: admin.otherName
              ? await this.decryptField(admin.otherName, "name")
              : null,
            email: await this.decryptField(admin.user.email, "email"),
            phone: await this.decryptField(admin.phone, "phone"),
            department: admin.department,
            institution: admin.institution,
            qualification: admin.qualification,
            specialization: admin.specialization,
            experience: admin.experience,
            dateJoined: admin.dateJoined,
            isActive: admin.user.isActive,
            passportUrl: admin.passportUrl,
            gender: admin.gender,
            userId: admin.userId,
            user: admin.user,
          };
        })
      );

      return {
        admins: decryptedAdmins,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      console.error("Error getting all admins:", error);
      throw error;
    }
  }

  /**
   * Search admins
   */
  static async searchAdmins(
    query: string,
    page: number = 1,
    limit: number = 10,
    filters?: {
      department?: string;
    }
  ) {
    try {
      const skip = (page - 1) * limit;

      const where: any = {};
      if (filters?.department) {
        where.department = filters.department;
      }

      const [admins, total] = await Promise.all([
        prisma.admin.findMany({
          where: {
            OR: [
              {
                user: {
                  name: {
                    contains: query,
                    mode: "insensitive",
                  },
                },
              },
              {
                department: {
                  contains: query,
                  mode: "insensitive",
                },
              },
              {
                employeeId: {
                  contains: query,
                  mode: "insensitive",
                },
              },
            ],
            ...where,
          },
          skip,
          take: limit,
          include: {
            user: {
              select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isActive: true,
                emailVerified: true,
                lastLoginAt: true,
                createdAt: true,
              },
            },
          },
        }),
        prisma.admin.count({ where }),
      ]);

      // Process each admin to extract employeeId
      const decryptedAdmins = await Promise.all(
        admins.map(async (admin) => {
          const employeeId = (admin as any).employeeId;
          
          return {
            id: admin.id,
            employeeId: employeeId || "",
            firstName: await this.decryptField(admin.firstName, "name"),
            lastName: await this.decryptField(admin.lastName, "name"),
            otherName: admin.otherName
              ? await this.decryptField(admin.otherName, "name")
              : null,
            email: await this.decryptField(admin.user.email, "email"),
            phone: await this.decryptField(admin.phone, "phone"),
            department: admin.department,
            institution: admin.institution,
            qualification: admin.qualification,
            specialization: admin.specialization,
            experience: admin.experience,
            dateJoined: admin.dateJoined,
            isActive: admin.user.isActive,
            passportUrl: admin.passportUrl,
            gender: admin.gender,
            userId: admin.userId,
            user: admin.user,
          };
        })
      );

      return {
        admins: decryptedAdmins,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      console.error("Error searching admins:", error);
      throw error;
    }
  }

  /**
   * Update admin last activity
   */
  static async updateLastActivity(adminId: string): Promise<void> {
    try {
      await prisma.admin.update({
        where: { id: adminId },
        data: { lastActivityAt: new Date() },
      });
    } catch (error) {
      console.error("Error updating admin last activity:", error);
      throw error;
    }
  }

  /**
   * Helper method to decrypt field
   */
  private static async decryptField(
    encryptedField: string,
    fieldType: "email" | "phone" | "name"
  ): Promise<string> {
    try {
      return await unprotectData(encryptedField, fieldType);
    } catch (error) {
      console.error("Error decrypting field:", error);
      throw error;
    }
  }
}