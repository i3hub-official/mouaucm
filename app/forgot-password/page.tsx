// File: app/forgot-password/page.tsx
"use client";
import { useState,useEffect  } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  BookOpen,
  ArrowRight,
  Home,
  Lock,
  CheckCircle,
  ArrowLeft,
  Key,
  Mail,
  AlertCircle,
} from "lucide-react";
import { ThemeToggle } from "@/app/components/theme-toggle";

export default function ForgotPasswordPage() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState("");
  const [touched, setTouched] = useState(false);

   useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null; // or a loading spinner
  }
  
  // Email validation
  const isValidEmail = (email: string) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setTouched(true);

    // Validate email
    if (!email.trim()) {
      setError("Email address is required");
      return;
    }

    if (!isValidEmail(email)) {
      setError("Please enter a valid email address");
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setIsSuccess(true);
      } else {
        // Handle specific error cases
        if (response.status === 429) {
          setError("Too many attempts. Please wait a few minutes before trying again.");
        } else if (response.status === 404) {
          setError("No account found with this email address.");
        } else {
          setError(data.message || "Failed to send reset link. Please try again.");
        }
      }
    } catch (err) {
      console.error("Forgot password error:", err);
      setError("Network error. Please check your connection and try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetForm = () => {
    setEmail("");
    setIsSuccess(false);
    setError("");
    setTouched(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-linear-to-br from-background via-accent/5 to-primary/5 p-4">
      <div className="w-full max-w-md bg-card border border-border rounded-xl p-8 shadow-lg">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <button
            onClick={() => router.back()}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft size={16} />
            Back
          </button>
          <ThemeToggle />
        </div>

        {/* Logo */}
        <div className="text-center mb-8">
          <div className="flex flex-col items-center gap-4 mb-6">
            <div className="p-3 bg-primary/10 rounded-2xl">
              <img
                src="/mouau_logo.webp"
                alt="MOUAU Logo"
                className="h-12 w-12 object-contain"
              />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground mb-2">
                MOUAU ClassMate
              </h1>
              <p className="text-muted-foreground">Reset Your Password</p>
            </div>
          </div>
        </div>

        {/* Success State */}
        {isSuccess && (
          <div className="text-center space-y-6">
            <div className="flex flex-col items-center justify-center space-y-4">
              {/* Success Icon */}
              <div className="p-4 bg-green-500/10 rounded-full">
                <CheckCircle className="h-12 w-12 text-green-500" />
              </div>

              {/* Success Message */}
              <div>
                <h2 className="text-2xl font-bold text-foreground mb-2">
                  Check Your Email
                </h2>
                <p className="text-muted-foreground mb-4">
                  We've sent a password reset link to:
                </p>
                <div className="flex items-center justify-center gap-2 bg-muted p-3 rounded-lg border border-border">
                  <Mail size={16} className="text-primary" />
                  <p className="font-mono text-sm">{email}</p>
                </div>
              </div>

              {/* Instructions */}
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 text-left w-full">
                <div className="flex items-start gap-3">
                  <AlertCircle className="h-4 w-4 text-blue-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-foreground mb-2">
                      What to do next:
                    </p>
                    <ul className="text-xs text-muted-foreground space-y-1.5">
                      <li className="flex items-start gap-2">
                        <span className="text-primary">•</span>
                        <span>Check your inbox for an email from MOUAU ClassMate</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-primary">•</span>
                        <span>Click the reset link in the email</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-primary">•</span>
                        <span>Create your new password</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-primary">•</span>
                        <span>Sign in with your new credentials</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-3 w-full">
                <Link
                  href="/signin"
                  className="flex-1 py-2.5 bg-primary text-sm text-white font-medium rounded-md hover:bg-primary/90 transition-colors text-center"
                >
                  Back to Sign In
                </Link>
                <Link
                  href="/"
                  className="flex-1 py-2.5 bg-muted text-sm text-foreground font-medium rounded-md hover:bg-muted/80 transition-colors text-center"
                >
                  Go to Home
                </Link>
              </div>

              {/* Help Text */}
              <div className="text-sm text-muted-foreground">
                <p>Didn't receive the email? </p>
                <button
                  onClick={handleResetForm}
                  className="text-primary hover:underline font-medium mt-1"
                >
                  Try again with a different email
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Reset Form */}
        {!isSuccess && (
          <>
            <div className="text-center mb-6">
              <div className="p-3 bg-primary/10 rounded-full inline-flex mb-4">
                <Lock className="h-6 w-6 text-primary" />
              </div>
              <h2 className="text-2xl font-bold text-foreground mb-2">
                Forgot Password?
              </h2>
              <p className="text-muted-foreground text-sm">
                Enter your email address and we'll send you a link to reset your password.
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Error Message */}
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
                  <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                  <p className="text-red-500 text-sm">{error}</p>
                </div>
              )}

              {/* Email Input */}
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-foreground mb-2"
                >
                  Email Address <span className="text-primary">*</span>
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (error) setError("");
                      setTouched(true);
                    }}
                    onBlur={() => setTouched(true)}
                    placeholder="you@example.com"
                    className={`w-full pl-10 pr-4 py-3 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/20 transition-colors ${
                      touched && !isValidEmail(email) && email
                        ? "border-red-500"
                        : "border-border"
                    }`}
                    disabled={isLoading}
                    autoComplete="email"
                  />
                </div>
                {touched && !isValidEmail(email) && email && (
                  <p className="text-xs text-red-500 mt-2">
                    Please enter a valid email address
                  </p>
                )}
                <p className="text-xs text-muted-foreground mt-2">
                  We'll send a reset link to this email address
                </p>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading || !isValidEmail(email)}
                className="w-full py-3 bg-primary text-white font-semibold rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                    <span>Sending...</span>
                  </>
                ) : (
                  <>
                    <span>Send Reset Link</span>
                    <ArrowRight size={18} />
                  </>
                )}
              </button>
            </form>

            {/* Additional Links */}
            <div className="mt-6 space-y-4">
              <Link
                href="/signin"
                className="inline-flex items-center gap-2 text-sm text-primary hover:underline font-medium transition-colors group"
              >
                <Key size={16} className="group-hover:scale-110 transition-transform" />
                Remember your password? Sign in
              </Link>

              {/* Security Notice */}
              <div className="bg-muted/30 rounded-lg p-4 border border-border">
                <div className="flex items-start gap-3">
                  <Lock className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-foreground mb-1">
                      Security Notice
                    </p>
                    <p className="text-xs text-muted-foreground">
                      The password reset link will expire in 1 hour. If you don't reset your 
                      password within this time, you'll need to request a new link.
                    </p>
                  </div>
                </div>
              </div>

              {/* Support Link */}
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  Need help?{" "}
                  <Link
                    href="/support"
                    className="text-primary hover:underline font-medium"
                  >
                    Contact support
                  </Link>
                </p>
              </div>
            </div>
          </>
        )}

        {/* Footer Links */}
        <div className="mt-8 pt-6 border-t border-border">
          <div className="flex flex-wrap justify-between items-center gap-4 text-xs text-muted-foreground">
            <Link href="/" className="hover:text-foreground transition-colors">
              ← Back to Home
            </Link>
            <div className="flex gap-4">
              <Link
                href="/privacy"
                className="hover:text-foreground transition-colors"
              >
                Privacy
              </Link>
              <Link
                href="/terms"
                className="hover:text-foreground transition-colors"
              >
                Terms
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}