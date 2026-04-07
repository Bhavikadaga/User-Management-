const { z } = require('zod');

const emailSchema = z.string().email("Invalid email");

const passwordSchema = z.string()
    .min(8, "Min 8 characters")
    .regex(/[A-Z]/, "Need one uppercase letter")
    .regex(/[a-z]/, "Need one lowercase letter")
    .regex(/[0-9]/, "Need one number")
    .regex(/[!@#$&*%^]/, "Need one special character");

const signupSchema = z.object({
    name: z.string().min(2, "Enter your name"),
    email: emailSchema,
    password: passwordSchema,
    confirmedPassword: z.string(),
}).refine(data => data.password === data.confirmedPassword, {
    message: "Passwords don't match",
    path: ["confirmedPassword"]
});

const loginSchema = z.object({
    email: emailSchema,
    password: z.string().min(1, "Password is required")
});

module.exports = { signupSchema, loginSchema };