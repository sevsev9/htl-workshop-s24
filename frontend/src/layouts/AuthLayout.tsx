import Link from "next/link";

type AuthLayoutProps = {
  header: {
    title: string;
    description: string;
  };
  children: React.ReactNode;
  link: {
    text: string;
    href: string;
  };
};

export const AuthLayout = ({ link, header, children }: AuthLayoutProps) => {
  return (
    <div className="flex flex-col gap-4 justify-center items-center h-full">
      <div className="text-center">
        <h2 className="text-3xl font-medium">{header.title}</h2>
        <p className="text-base text-gray-500">{header.description}</p>
      </div>

      <div className="p-4 rouned-xl flex flex-col max-w-sm gap-2 w-full">
        {children}
      </div>

      <Link href={link.href} className="hover:underline">
        {link.text}
      </Link>
    </div>
  );
};
