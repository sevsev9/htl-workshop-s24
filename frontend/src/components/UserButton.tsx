import React from "react";
import { useRouter } from "next/router";
import { LogOutIcon, UserIcon } from "lucide-react";
// components
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useUserContext } from "@/context/AuthContext";

export default function UserButton() {
  const isAuthed = false;
  //todo create this
  // const { isAuthed } = useUserContext();
  const router = useRouter();

  const handleSignInClick = () => {
    router.push("/auth/login");
  };

  if (!isAuthed) {
    return <Button onClick={handleSignInClick}>Sign in</Button>;
  }

  return <UserDropdown />;
}

function UserDropdown() {
  // todo implement
  const router = useRouter();
  const { user } = useUserContext();
  // const { logout } = useAuthService();

  const items = [
    {
      label: "Profile",
      Icon: UserIcon,
      onClick: () => router.push("/profile"),
    },
    {
      label: "Logout",
      Icon: LogOutIcon,
      // onClick: logout,
      onClick: () => {},
    },
  ];

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline">{user.username}</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuLabel>{user.email}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {items.map(({ onClick, Icon, label }, i) => {
          return (
            <DropdownMenuItem
              key={i}
              className="cursor-pointer gap-4"
              onClick={onClick}
            >
              <Icon size={16} />
              {label}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
