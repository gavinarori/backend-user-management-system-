import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { generateOTP, sendOTP } from '../utils/otp';
import { hashPassword, comparePassword } from '../utils/password';
import { PrismaClient } from '@prisma/client';

interface Context {
  user?: { userId: string };
  prisma: PrismaClient;
}

interface User {
  id: string;
  email: string;
  password: string;
  isVerified: boolean;
  otp?: string;
  otpExpiry?: Date;
}

const resolvers = {
  Query: {
    me: async (_: unknown, __: unknown, { user, prisma }: Context) => {
      if (!user) throw new Error("Not authenticated");
      return prisma.user.findUnique({ where: { id: user.userId } });
    },
  },

  Mutation: {
    registerUser: async (_: unknown, { email, password }: { email: string; password: string }, { prisma }: Context) => {
      const hashedPassword = await hashPassword(password);
      const otp = generateOTP();
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 mins expiry

      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          otp,
          otpExpiry,
        },
      });

      await sendOTP(email, otp);

      return { token: null, user };
    },

    loginUser: async (_: unknown, { email, password }: { email: string; password: string }, { prisma }: Context) => {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) throw new Error("User not found");

      const isPasswordValid = await comparePassword(password, user.password);
      if (!isPasswordValid) throw new Error("Incorrect password");

      if (!user.isVerified) throw new Error("Account not verified");

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET as string, { expiresIn: '1h' });
      return { token, user };
    },

    verifyAccount: async (_: unknown, { email, otp }: { email: string; otp: string }, { prisma }: Context) => {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) throw new Error("User not found");

      if (user.otp !== otp || user.otpExpiry! < new Date()) {
        throw new Error("Invalid or expired OTP");
      }

      const updatedUser = await prisma.user.update({
        where: { email },
        data: { isVerified: true, otp: null, otpExpiry: null },
      });

      return updatedUser;
    },

    requestPasswordReset: async (_: unknown, { email }: { email: string }, { prisma }: Context) => {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) throw new Error("User not found");

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET as string, { expiresIn: '15m' });
      // Send password reset email (not implemented here, add your logic)
      return true;
    },

    resetPassword: async (_: unknown, { token, password }: { token: string; password: string }, { prisma }: Context) => {
      const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { userId: string };
      const hashedPassword = await hashPassword(password);

      await prisma.user.update({
        where: { id: decoded.userId },
        data: { password: hashedPassword },
      });

      return true;
    },
  },
};

export default resolvers;
