import { Head } from "fresh/runtime";
import { define } from "../utils.ts";
import SpfValidator from "../islands/SpfValidator.tsx";

export default define.page(function Home() {
  return (
    <div class="min-h-screen bg-[#fafafa]">
      <Head>
        <title>SPF Validator</title>
      </Head>
      <div class="px-6 md:px-12 py-8">
        <div class="max-w-4xl mx-auto">
          <h1 class="text-2xl font-normal text-[#111] tracking-tight mb-2">
            SPF Validator
          </h1>
          <p class="text-[#666] text-sm mb-8">
            Validate SPF records according to RFC 7208. Expands all include
            lookups and checks DNS lookup count (max 10 allowed).
          </p>
          <SpfValidator />
        </div>
      </div>
    </div>
  );
});
