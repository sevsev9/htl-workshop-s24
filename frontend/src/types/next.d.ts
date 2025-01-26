import { type GetStaticProps, type NextPage } from "next";
import { type AppProps } from "next/app";
import { type Session } from "next-auth";
import { type ReactElement, type ReactNode } from "react";
import { type AbstractIntlMessages } from "next-intl";

type GetStaticPropsWithLocale = GetStaticProps & { locale: string };

type NextPageWithLayout<P = object, IP = P> = NextPage<P, IP> & {
  getLayout?: (page: ReactElement, pageProps?: object) => ReactNode;
};

type AppPropsWithLayout = AppProps<PageProps> & {
  Component: NextPageWithLayout<{
    getLayout?: (page: ReactElement, pageProps?: object) => ReactNode;
  }>;
};
