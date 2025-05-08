import React, { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { startRegistration } from "@simplewebauthn/browser";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { HiFingerPrint, HiTrash } from "react-icons/hi";
import { LuKey, LuPlus } from "react-icons/lu";
import ActivityIndicator from "@/components/indicators/activity-indicator";

interface Credential {
  id: string;
  created_at: string;
  aaguid: string;
  transports?: string[];
}

interface PasskeyManagerProps {
  forUser?: string; // Optional prop to manage passkeys for a specific user
}

const PasskeyManager: React.FC<PasskeyManagerProps> = ({ forUser }) => {
  const { t } = useTranslation(["components/passkey", "common"]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);
  const [adminMode] = useState(!!forUser); // If forUser is provided, we're in admin mode

  // Fetch user's passkeys
  const fetchPasskeys = async () => {
    setLoading(true);
    try {
      let url = "/webauthn/credentials";

      // If we're in admin mode, fetch passkeys for the specified user
      if (adminMode && forUser) {
        url = `/webauthn/credentials/${encodeURIComponent(forUser)}`;
      }

      const response = await axios.get(url);
      setCredentials(response.data.credentials || []);
    } catch (error) {
      console.error("Failed to fetch passkeys:", error);
      toast.error(t("errors.fetchFailed"), {
        position: "top-center",
      });
    } finally {
      setLoading(false);
    }
  };

  // Load passkeys when component mounts
  useEffect(() => {
    fetchPasskeys();
  }, [forUser]);

  // Register a new passkey
  const registerPasskey = async () => {
    setRegistering(true);
    try {
      // 1. Get registration options from server
      let url = "/webauthn/registration-options";

      // If we're in admin mode, request options for the specified user
      if (adminMode && forUser) {
        url = `/webauthn/registration-options/${encodeURIComponent(forUser)}`;
      }

      const optionsResponse = await axios.get(url);

      // 2. Start WebAuthn registration
      const attResp = await startRegistration(optionsResponse.data);

      // 3. Send response to server to verify and save
      let registerUrl = "/webauthn/register";

      // If we're in admin mode, register for the specified user
      if (adminMode && forUser) {
        registerUrl = `/webauthn/register/${encodeURIComponent(forUser)}`;
      }

      await axios.post(registerUrl, attResp);

      // 4. Refresh the list of credentials
      await fetchPasskeys();

      toast.success(t("success.registered"), {
        position: "top-center",
      });
    } catch (error) {
      console.error("Failed to register passkey:", error);
      let errorMessage = t("errors.registrationFailed");

      // Handle specific errors
      if (error instanceof Error) {
        if (error.name === 'NotAllowedError') {
          errorMessage = t("errors.notAllowed");
        } else if (error.name === 'NotSupportedError') {
          errorMessage = t("errors.notSupported");
        } else {
          errorMessage = error.message;
        }
      }

      toast.error(errorMessage, {
        position: "top-center",
      });
    } finally {
      setRegistering(false);
    }
  };

  // Delete all passkeys
  const deleteAllPasskeys = async () => {
    setLoading(true);
    try {
      let url = "/webauthn/credentials";

      // If we're in admin mode, delete passkeys for the specified user
      if (adminMode && forUser) {
        url = `/webauthn/credentials/${encodeURIComponent(forUser)}`;
      }

      await axios.put(url);
      setCredentials([]);
      setShowConfirmDelete(false);
      toast.success(t("success.deleted"), {
        position: "top-center",
      });
    } catch (error) {
      console.error("Failed to delete passkeys:", error);
      toast.error(t("errors.deleteFailed"), {
        position: "top-center",
      });
    } finally {
      setLoading(false);
    }
  };

  // Format date for display
  const formatDate = (dateString: string) => {
    if (!dateString || dateString === "Unknown") return t("unknown");
    try {
      return new Date(Number(dateString) * 1000).toLocaleString();
    } catch (e) {
      return dateString;
    }
  };

  // Get the appropriate title
  const getTitle = () => {
    if (adminMode && forUser) {
      return t("titleForUser", { user: forUser });
    }
    return t("title");
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <HiFingerPrint className="mr-2" />
            {getTitle()}
          </CardTitle>
          <CardDescription>{t("description")}</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-4">
              <ActivityIndicator />
            </div>
          ) : credentials.length === 0 ? (
            <div className="text-center py-4 text-muted-foreground">
              {adminMode
                ? t("noPasskeysForUser", { user: forUser })
                : t("noPasskeys")}
            </div>
          ) : (
            <div className="space-y-2">
              {credentials.map((credential) => (
                <div
                  key={credential.id}
                  className="flex items-center justify-between p-3 border rounded-md"
                >
                  <div className="flex items-center space-x-3">
                    <LuKey className="text-primary" />
                    <div>
                      <div className="font-medium">
                        {t("deviceName", { id: credential.id.substring(0, 8) })}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {t("registeredOn")}: {formatDate(credential.created_at)}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button
            variant="outline"
            onClick={() => setShowConfirmDelete(true)}
            disabled={loading || credentials.length === 0}
            className="text-destructive border-destructive hover:bg-destructive/10"
          >
            <HiTrash className="mr-2 h-4 w-4" />
            {t("removeAll")}
          </Button>
          <Button onClick={registerPasskey} disabled={registering || loading}>
            {registering ? (
              <ActivityIndicator />
            ) : (
              <>
                <LuPlus className="mr-2 h-4 w-4" />
                {t("register")}
              </>
            )}
          </Button>
        </CardFooter>
      </Card>

      {/* Confirmation Dialog for Deleting All Passkeys */}
      <Dialog open={showConfirmDelete} onOpenChange={setShowConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("confirmDelete.title")}</DialogTitle>
            <DialogDescription>
              {adminMode
                ? t("confirmDelete.descriptionForUser", { user: forUser })
                : t("confirmDelete.description")}
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end space-x-2 pt-4">
            <Button
              variant="outline"
              onClick={() => setShowConfirmDelete(false)}
              disabled={loading}
            >
              {t("cancel", { ns: "common" })}
            </Button>
            <Button
              variant="destructive"
              onClick={deleteAllPasskeys}
              disabled={loading}
            >
              {loading ? <ActivityIndicator /> : t("delete", { ns: "common" })}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default PasskeyManager;