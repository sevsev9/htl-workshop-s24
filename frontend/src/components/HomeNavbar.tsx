import Link from "next/link";
import UserButton from "@/components/UserButton";

export default function HomeNavbar() {
  return (
    <nav className="bg-white border-b fixed top-0 inset-x-0">
      <div className="container mx-auto flex items-center justify-between h-14">
        <Link href={"/"}>Home</Link>
        <UserButton />
      </div>
    </nav>
  );
}
