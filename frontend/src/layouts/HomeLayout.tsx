import HomeNavbar from "@/components/HomeNavbar";

export default function HomeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="h-screen">
      <HomeNavbar />
      <main className="container mx-auto pt-16 h-full">{children}</main>
    </div>
  );
}
