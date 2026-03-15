// lib/services/s/studentRegistrationService.ts
import { prisma } from "@/lib/server/prisma";
import { StudentRegistrationData } from "@/lib/types/s/index";
import {
  protectData,
  verifyPassword,
  validatePasswordStrength,
} from "@/lib/security/dataProtection";
import { generateVerificationToken } from "@/lib/utils";

// Default profile picture (secure, immutable Cloudinary URL)
const DEFAULT_PROFILE_PICTURE =
  "https://res.cloudinary.com/djimok28g/image/upload/v1763579659/ock8lrmvr3elhho1dhuw.jpg";

export class StudentRegistrationService {
  /**
   * Register a new student — Fully Secure & NDPC-Compliant
   */
  static async registerStudent(data: StudentRegistrationData) {
    const {
      firstName,
      lastName,
      otherName = "",
      gender,
      dateOfBirth,
      email,
      phone,
      matricNumber = "",
      jambRegNumber,
      nin,
      department,
      college,
      // course is not destructured - we'll use department instead
      admissionYear,
      password,
      passportUrl,
      state = "",
      lga = "",
    } = data;

    // === VALIDATION ===
    if (!email?.trim()) throw new Error("Email is required");
    if (!phone?.trim()) throw new Error("Phone number is required");
    if (!password) throw new Error("Password is required");
    if (!nin?.trim()) throw new Error("NIN is required");
    if (!jambRegNumber?.trim())
      throw new Error("JAMB Registration Number is required");
    if (!department?.trim()) throw new Error("Department is required");
    if (!college?.trim()) throw new Error("College is required");
  
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
      throw new Error(`Weak password: ${passwordValidation.errors.join(", ")}`);
    }

    const finalPassportUrl = passportUrl?.trim() || DEFAULT_PROFILE_PICTURE;

    try {
      // === PROTECT SENSITIVE DATA USING CORRECT TIERS ===
      const [
        protectedPassword,
        protectedEmail,
        protectedPhone,
        protectedNin,
        protectedJamb,
        protectedMatric,
        protectedFirstName,
        protectedLastName,
        protectedOtherName,
        protectedState,
        protectedLga,
      ] = await Promise.all([
        protectData(password, "password"),
        protectData(email.trim(), "email"),
        protectData(phone.trim(), "phone"),
        protectData(nin.trim(), "nin"),
        protectData(jambRegNumber.trim(), "jamb"),
        matricNumber
          ? protectData(matricNumber.trim(), "matric")
          : { encrypted: "", searchHash: "" },
        protectData(firstName.trim(), "name"),
        protectData(lastName.trim(), "name"), 
        otherName ? protectData(otherName.trim(), "name") : { encrypted: "" },
        state ? protectData(state.trim(), "location") : { encrypted: "" },
        lga ? protectData(lga.trim(), "location") : { encrypted: "" },
      ]);

      // Extract search hashes
      const emailSearchHash = protectedEmail.searchHash!;
      const phoneSearchHash = protectedPhone.searchHash!;
      const ninSearchHash = protectedNin.searchHash!;
      const jambSearchHash = protectedJamb.searchHash!;
      const matricSearchHash = protectedMatric.searchHash || "";

      // === UNIQUENESS CHECKS ===
      const [
        existingNin,
        existingEmailUser,
        existingEmailStudent,
        existingPhone,
        existingJamb,
        existingMatric,
      ] = await Promise.all([
        prisma.student.findFirst({ where: { ninSearchHash } }),
        prisma.user.findFirst({ where: { email: protectedEmail.encrypted } }),
        prisma.student.findFirst({ where: { emailSearchHash } }),
        prisma.student.findFirst({ where: { phoneSearchHash } }),
        prisma.student.findFirst({
          where: { jambRegSearchHash: jambSearchHash },
        }),
        matricNumber
          ? prisma.student.findUnique({
              where: { matricNumber: matricNumber.trim().toUpperCase() },
            })
          : null,
      ]);

      if (existingNin) throw new Error("NIN already registered");
      if (existingEmailUser || existingEmailStudent)
        throw new Error("Email already in use");
      if (existingPhone) throw new Error("Phone number already registered");
      if (existingJamb)
        throw new Error("JAMB Registration Number already registered");
      if (existingMatric)
        throw new Error("Matriculation Number already registered");

      // === CREATE USER ACCOUNT ===
      const user = await prisma.user.create({
        data: {
          name:
            `${lastName.trim()} ${firstName.trim()}` +
            (otherName ? ` ${otherName.trim()}` : ""),
          email: protectedEmail.encrypted,
          passwordHash: protectedPassword.encrypted,
          role: "STUDENT",
          isActive: false,
          image: finalPassportUrl,
        },
      });

      // === CREATE STUDENT PROFILE ===
      const student = await prisma.student.create({
        data: {
          userId: user.id,
          matricNumber: matricNumber.trim().toUpperCase(),
          jambRegNumber: protectedJamb.encrypted,
          nin: protectedNin.encrypted,
          firstName: protectedFirstName.encrypted,
          lastName: protectedLastName.encrypted,
          otherName: protectedOtherName.encrypted || null,
          gender: gender || null,
          dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null,
          email: protectedEmail.encrypted,
          emailSearchHash: emailSearchHash || null,
          phone: protectedPhone.encrypted,
          phoneSearchHash: phoneSearchHash || null,
          jambRegSearchHash: jambSearchHash || null,
          ninSearchHash: ninSearchHash || null,
          matricSearchHash: matricSearchHash || null,
          // Set course to the same value as department
          course: department.trim(), 
          department: department.trim(),
          college: college.trim(),
          admissionYear: admissionYear ? Number(admissionYear) : null,
          passportUrl: finalPassportUrl,
          state: protectedState.encrypted || "",
          lga: protectedLga.encrypted || "",
        },
      });

      // === EMAIL VERIFICATION TOKEN ===
      const token = generateVerificationToken();
      await prisma.verificationToken.create({
        data: {
          identifier: user.id,
          token,
          expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      });

      // === AUDIT LOG ===
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: "STUDENT_REGISTERED",
          resourceType: "STUDENT",
          resourceId: student.id,
          details: {
            usedDefaultPassport: !passportUrl,
            hasMatricNumber: !!matricNumber,
            department: department.trim(),
            college: college.trim(),
            course: department.trim(), // Log that course = department
            identifiers: {
              nin: nin.slice(0, 4) + "****" + nin.slice(-3),
              jamb:
                jambRegNumber.slice(0, 4) + "****" + jambRegNumber.slice(-2),
              email:
                email.split("@")[0].slice(0, 3) + "***@" + email.split("@")[1],
            },
          },
        },
      });

      return {
        success: true,
        userId: user.id,
        studentId: student.id,
        verificationToken: token,
        usedDefaultProfile: !passportUrl,
        message: "Registration successful. Please verify your email.",
      };
    } catch (error: any) {
      console.error("Registration failed:", error);
      throw new Error(error.message || "Registration failed");
    }
  }

  // === OTHER METHODS ===

  static async verifyEmail(token: string) {
    const vt = await prisma.verificationToken.findUnique({ where: { token } });
    if (!vt || vt.expires < new Date())
      throw new Error("Invalid or expired token");

    await prisma.$transaction([
      prisma.user.update({
        where: { id: vt.identifier },
        data: { isActive: true, emailVerified: new Date() },
      }),
      prisma.verificationToken.delete({ where: { token } }),
      prisma.auditLog.create({
        data: {
          userId: vt.identifier,
          action: "EMAIL_VERIFIED",
          resourceType: "USER",
          resourceId: vt.identifier,
        },
      }),
    ]);

    return { success: true, message: "Email verified" };
  }

  static async checkNINAvailability(nin: string) {
    const { searchHash } = await protectData(nin.trim(), "nin");
    return !(await prisma.student.findFirst({
      where: { ninSearchHash: searchHash },
    }));
  }

  static async checkJambAvailability(jamb: string) {
    const { searchHash } = await protectData(jamb.trim(), "jamb");
    return !(await prisma.student.findFirst({
      where: { jambRegSearchHash: searchHash },
    }));
  }

  static async checkMatricAvailability(matric: string) {
    return !(await prisma.student.findUnique({
      where: { matricNumber: matric.trim().toUpperCase() },
    }));
  }

  static async checkEmailAvailability(email: string) {
    const { encrypted, searchHash } = await protectData(email.trim(), "email");
    const [user, student] = await Promise.all([
      prisma.user.findFirst({ where: { email: encrypted } }),
      prisma.student.findFirst({ where: { emailSearchHash: searchHash } }),
    ]);
    return !user && !student;
  }

  static async checkPhoneAvailability(phone: string) {
    const { searchHash } = await protectData(phone.trim(), "phone");
    return !(await prisma.student.findFirst({
      where: { phoneSearchHash: searchHash },
    }));
  }

  /**
   * Update student profile
   */
  static async updateStudentProfile(
    studentId: string,
    data: Partial<StudentRegistrationData>
  ) {
    try {
      const {
        firstName,
        lastName,
        otherName,
        gender,
        dateOfBirth,
        email,
        phone,
        department,
        college,
        admissionYear,
        passportUrl,
        state,
        lga,
      } = data;

      const updateData: any = {};

      if (firstName) {
        const protectedFirstName = await protectData(firstName.trim(), "name");
        updateData.firstName = protectedFirstName.encrypted;
      }

      if (lastName) {
        const protectedLastName = await protectData(lastName.trim(), "name");
        updateData.lastName = protectedLastName.encrypted;
      }

      if (otherName) {
        const protectedOtherName = await protectData(otherName.trim(), "name");
        updateData.otherName = protectedOtherName.encrypted;
      }

      if (gender) {
        updateData.gender = gender;
      }

      if (dateOfBirth) {
        updateData.dateOfBirth = new Date(dateOfBirth);
      }

      if (email) {
        const protectedEmail = await protectData(email.trim(), "email");
        updateData.email = protectedEmail.encrypted;
        updateData.emailSearchHash = protectedEmail.searchHash;
      }

      if (phone) {
        const protectedPhone = await protectData(phone.trim(), "phone");
        updateData.phone = protectedPhone.encrypted;
        updateData.phoneSearchHash = protectedPhone.searchHash;
      }

      if (department) {
        updateData.department = department.trim();
        // Also update course to match department
        updateData.course = department.trim();
      }

      if (college) {
        updateData.college = college.trim();
      }

      if (admissionYear) {
        updateData.admissionYear = Number(admissionYear);
      }

      if (passportUrl) {
        updateData.passportUrl = passportUrl;
      }

      if (state) {
        const protectedState = await protectData(state.trim(), "location");
        updateData.state = protectedState.encrypted;
      }

      if (lga) {
        const protectedLga = await protectData(lga.trim(), "location");
        updateData.lga = protectedLga.encrypted;
      }

      const student = await prisma.student.update({
        where: { id: studentId },
        data: updateData,
      });

      await prisma.auditLog.create({
        data: {
          userId: student.userId,
          action: "STUDENT_PROFILE_UPDATED",
          resourceType: "STUDENT",
          resourceId: student.id,
          details: {
            updatedFields: Object.keys(updateData),
          },
        },
      });

      return {
        success: true,
        message: "Profile updated successfully.",
        student,
      };
    } catch (error) {
      console.error("Student profile update error:", error);
      throw error;
    }
  }

  /**
   * Get student profile by ID
   */
  static async getStudentProfile(studentId: string) {
    try {
      const student = await prisma.student.findUnique({
        where: { id: studentId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              emailVerified: true,
              isActive: true,
              createdAt: true,
            },
          },
        },
      });

      if (!student) {
        throw new Error("Student not found");
      }

      return {
        success: true,
        student,
      };
    } catch (error) {
      console.error("Get student profile error:", error);
      throw error;
    }
  }
}