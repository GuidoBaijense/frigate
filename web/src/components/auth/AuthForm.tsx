"use client";

import * as React from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";

import { baseUrl } from "../../api/baseUrl";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import ActivityIndicator from "@/components/indicators/activity-indicator";
import axios, { AxiosError } from "axios";
import { toast } from "sonner";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { AuthContext } from "@/context/auth-context";
import { useTranslation } from "react-i18next";
import { FaKey } from "react-icons/fa";
import { HiFingerPrint } from "react-icons/hi";
import { MdOutlinePersonAddAlt } from "react-icons/md";

interface UserAuthFormProps extends React.HTMLAttributes<HTMLDivElement> {}

export function UserAuthForm({ className, ...props }: UserAuthFormProps) {
  const { t } = useTranslation(["components/auth"]);
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const [passkeyLoading, setPasskeyLoading] = React.useState<boolean>(false);
  const [registerPasskeyLoading, setRegisterPasskeyLoading] = React.useState<boolean>(false);
  const [username, setUsername] = React.useState<string>("");
  const [isLoggedIn, setIsLoggedIn] = React.useState<boolean>(false);
  const { login } = React.useContext(AuthContext);

  const formSchema = z.object({
    user: z.string().min(1, t("form.errors.usernameRequired")),
    password: z.string().min(1, t("form.errors.passwordRequired")),
  });

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    mode: "onChange",
    defaultValues: { user: "", password: "" },
  });

  // When username changes, update the state
  React.useEffect(() => {
    const subscription = form.watch((value, { name }) => {
      if (name === "user" && value.user) {
        setUsername(value.user);
      }
    });
    return () => subscription.unsubscribe();
  }, [form.watch]);

  // Check if the user is already logged in
  React.useEffect(() => {
    const checkLoginStatus = async () => {
      try {
        const profileRes = await axios.get("/profile", { withCredentials: true });
        setIsLoggedIn(true);
        login({
          username: profileRes.data.username,
          role: profileRes.data.role || "viewer",
        });
      } catch (error) {
        // Not logged in, do nothing
        setIsLoggedIn(false);
      }
    };

    checkLoginStatus();
  }, [login]);

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    try {
      await axios.post(
        "/login",
        {
          user: values.user,
          password: values.password,
        },
        {
          headers: { "X-CSRF-TOKEN": "1" },
        },
      );
      const profileRes = await axios.get("/profile", { withCredentials: true });
      login({
        username: profileRes.data.username,
        role: profileRes.data.role || "viewer",
      });
      window.location.href = baseUrl;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const err = error as AxiosError;
        if (err.response?.status === 429) {
          toast.error(t("form.errors.rateLimit"), {
            position: "top-center",
          });
        } else if (err.response?.status === 401) {
          toast.error(t("form.errors.loginFailed"), {
            position: "top-center",
          });
        } else {
          toast.error(t("form.errors.unknownError"), {
            position: "top-center",
          });
        }
      } else {
        toast.error(t("form.errors.webUnknownError"), {
          position: "top-center",
        });
      }

      setIsLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    if (!username) {
      toast.error(t("form.errors.usernamePasskey"), {
        position: "top-center",
      });
      return;
    }

    setPasskeyLoading(true);
    try {
      // Fetch authentication options from the backend
      const optionsResponse = await axios.get(`/webauthn/authentication-options?username=${encodeURIComponent(username)}`);
      if (!optionsResponse.data) {
        throw new Error("Failed to fetch authentication options");
      }

      // Start WebAuthn authentication
      const assertion = await startAuthentication(optionsResponse.data);

      // Send the assertion to the backend for verification
      const authenticateResponse = await axios.post("/webauthn/authenticate", assertion, {
        headers: { "X-CSRF-TOKEN": "1" }
      });

      if (authenticateResponse.status !== 200) {
        throw new Error("Failed to authenticate with passkey");
      }

      // Log in the user
      const profileRes = await axios.get("/profile", { withCredentials: true });
      login({
        username: profileRes.data.username,
        role: profileRes.data.role || "viewer",
      });
      window.location.href = baseUrl;
    } catch (error) {
      console.error("Passkey authentication failed:", error);
      let errorMessage = t("form.errors.passkeyFailed");

      // Handle different error cases
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        if (axiosError.response?.status === 404) {
          errorMessage = t("form.errors.userNotFound");
        } else if (axiosError.response?.status === 400) {
          const responseData = axiosError.response.data as any;
          if (responseData?.detail?.includes("No WebAuthn credentials")) {
            errorMessage = t("form.errors.noPasskey");
          }
        }
      } else {
        // Non-Axios error, could be browser-related
        if (error instanceof Error && error.name === "NotAllowedError") {
          errorMessage = t("form.errors.passkeyNotAllowed");
        } else if (error instanceof Error) {
          errorMessage = error.message;
        }
      }

      toast.error(errorMessage, {
        position: "top-center",
      });
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleRegisterPasskey = async () => {
    if (!isLoggedIn) {
      toast.error(t("form.errors.loginRequired", "You must be logged in to register a passkey"), {
        position: "top-center",
      });
      return;
    }

    setRegisterPasskeyLoading(true);
    try {
      // Fetch registration options from the backend
      const optionsResponse = await axios.get("/webauthn/registration-options");
      if (!optionsResponse.data) {
        throw new Error("Failed to fetch registration options");
      }

      // Start WebAuthn registration
      const attestation = await startRegistration(optionsResponse.data);

      // Send the attestation to the backend for verification
      const registerResponse = await axios.post("/webauthn/register", attestation, {
        headers: { "X-CSRF-TOKEN": "1" }
      });

      if (registerResponse.status !== 200) {
        throw new Error("Failed to register passkey");
      }

      toast.success(t("form.success.passkeyRegistered", "Passkey registered successfully"), {
        position: "top-center",
      });
    } catch (error) {
      console.error("Passkey registration failed:", error);
      let errorMessage = t("form.errors.passkeyRegistrationFailed", "Failed to register passkey");

      // Handle different error cases
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        if (axiosError.response?.status === 401) {
          errorMessage = t("form.errors.unauthorized", "Unauthorized");
        } else if (axiosError.response?.data && typeof axiosError.response.data === 'object') {
          const responseData = axiosError.response.data as any;
          if (responseData.detail) {
            errorMessage = responseData.detail;
          }
        }
      } else {
        // Non-Axios error, could be browser-related
        if (error instanceof Error && error.name === "NotAllowedError") {
          errorMessage = t("form.errors.passkeyNotAllowed", "User declined to create passkey");
        } else if (error instanceof Error) {
          errorMessage = error.message;
        }
      }

      toast.error(errorMessage, {
        position: "top-center",
      });
    } finally {
      setRegisterPasskeyLoading(false);
    }
  };

  return (
    <div className={cn("grid gap-6", className)} {...props}>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <FormField
            name="user"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t("form.user")}</FormLabel>
                <FormControl>
                  <Input
                    className="text-md w-full border border-input bg-background p-2 hover:bg-accent hover:text-accent-foreground dark:[color-scheme:dark]"
                    autoFocus
                    {...field}
                  />
                </FormControl>
              </FormItem>
            )}
          />
          <FormField
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t("form.password")}</FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    className="text-md w-full border border-input bg-background p-2 dark:[color-scheme:dark]"
                    {...field}
                  />
                </FormControl>
              </FormItem>
            )}
          />
          <Button
            disabled={isLoading}
            className="w-full justify-center"
            type="submit"
          >
            {isLoading ? (
              <ActivityIndicator />
            ) : (
              <>
                <FaKey className="mr-2" />
                {t("form.login")}
              </>
            )}
          </Button>
        </form>
      </Form>

      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t"></span>
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">
            {t("form.or")}
          </span>
        </div>
      </div>

      <Button
        variant="outline"
        type="button"
        disabled={passkeyLoading}
        className="w-full justify-center"
        onClick={handlePasskeyLogin}
      >
        {passkeyLoading ? (
          <ActivityIndicator />
        ) : (
          <>
            <HiFingerPrint className="mr-2 h-4 w-4" />
            {t("form.loginWithPasskey")}
          </>
        )}
      </Button>

      {isLoggedIn && (
        <>
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t"></span>
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">
                {t("form.manage", "Manage")}
              </span>
            </div>
          </div>

          <Button
            variant="outline"
            type="button"
            disabled={registerPasskeyLoading}
            className="w-full justify-center"
            onClick={handleRegisterPasskey}
          >
            {registerPasskeyLoading ? (
              <ActivityIndicator />
            ) : (
              <>
                <MdOutlinePersonAddAlt className="mr-2 h-4 w-4" />
                {t("form.registerPasskey", "Register Passkey")}
              </>
            )}
          </Button>
        </>
      )}
    </div>
  );
}
