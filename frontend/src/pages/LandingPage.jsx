import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, ChevronDown } from "lucide-react";

export default function LandingPage() {
  const [showNavbar, setShowNavbar] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setShowNavbar(window.scrollY > 120);
    };

    window.addEventListener("scroll", handleScroll);

    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <div className="bg-[#F0E7D3] text-[#2B1D16] overflow-hidden">
      {/* ================= NAVBAR ================= */}
      <motion.nav
        initial={{ y: -100, opacity: 0 }}
        animate={{
          y: showNavbar ? 0 : -100,
          opacity: showNavbar ? 1 : 0,
        }}
        transition={{ duration: 0.5 }}
        className="fixed top-0 left-0 w-full z-50 backdrop-blur-md bg-[#F0E7D3]/80 border-b border-[#d8c7ab]"
      >
        <div className="max-w-7xl mx-auto px-8 py-5 flex items-center justify-between">
          <h2 className="font-serif text-2xl tracking-wide">
            SkillChain
          </h2>

          <div className="flex items-center gap-10 text-sm tracking-wide">
            <Link to="/verify" className="hover:text-[#B56A3E] transition">
              Verify
            </Link>

            <Link to="/artisan" className="hover:text-[#B56A3E] transition">
              Artisans
            </Link>

            <Link to="/institution" className="hover:text-[#B56A3E] transition">
              Institutions
            </Link>
          </div>
        </div>
      </motion.nav>

      {/* ================= HERO SECTION ================= */}
      <section className="relative min-h-screen flex items-center justify-center px-6">
        {/* Background Texture */}
        <div className="absolute inset-0 opacity-[0.06] bg-[url('https://www.transparenttextures.com/patterns/old-map.png')]" />

        {/* Top Left Motif */}
        <div className="absolute top-0 left-0 w-[420px] h-[420px] opacity-[0.08] rounded-full border border-[#B56A3E]" />

        {/* Decorative Gradient */}
        <div className="absolute bottom-[-120px] right-[-80px] w-[500px] h-[500px] rounded-full bg-[#D8B38A]/20 blur-3xl" />

        <div className="relative z-10 max-w-6xl mx-auto grid lg:grid-cols-2 gap-12 items-center">
          {/* LEFT CONTENT */}
          <motion.div
            initial={{ opacity: 0, y: 60 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1 }}
          >
            <div className="flex items-center gap-2 mb-6 text-[#9B5E38] uppercase tracking-[0.3em] text-xs">
              <Shield size={14} />
              Blockchain Verified Heritage
            </div>

            <h1 className="font-serif text-[5rem] md:text-[7rem] leading-[0.9] tracking-[-0.04em] mb-8">
              SkillChain
            </h1>

            <div className="w-24 h-[1px] bg-[#B56A3E] mb-8" />

            <p className="text-xl md:text-2xl leading-relaxed text-[#5C4636] max-w-xl mb-10 font-light">
              Preserving human craft through verifiable provenance,
              decentralized identity, and permanent digital heritage.
            </p>

            <div className="flex flex-wrap gap-5">
              <Link
                to="/verify"
                className="px-8 py-4 bg-[#B56A3E] text-white rounded-sm tracking-wide hover:bg-[#9f5730] transition duration-300 shadow-lg"
              >
                Verify Artwork
              </Link>

              <Link
                to="/artisan"
                className="px-8 py-4 border border-[#B56A3E] text-[#B56A3E] rounded-sm tracking-wide hover:bg-[#B56A3E] hover:text-white transition duration-300"
              >
                Register Artisan
              </Link>
            </div>
          </motion.div>

          {/* RIGHT SIDE CERTIFICATE */}
          <motion.div
            initial={{ opacity: 0, rotate: 6, y: 40 }}
            animate={{ opacity: 1, rotate: -6, y: 0 }}
            transition={{ duration: 1.2 }}
            className="relative hidden lg:flex justify-center"
          >
            <div className="relative bg-[#E8D9BE] shadow-2xl border border-[#d7c3a3] w-[420px] h-[560px] p-10 rotate-[-8deg]">
              {/* Paper texture */}
              <div className="absolute inset-0 opacity-[0.05] bg-[url('https://www.transparenttextures.com/patterns/paper-fibers.png')]" />

              <div className="relative z-10">
                <div className="text-xs tracking-[0.3em] uppercase text-[#8A674F] mb-8">
                  Certificate of Authenticity
                </div>

                <h3 className="font-serif text-4xl leading-tight mb-10">
                  Verified on Blockchain
                </h3>

                <div className="space-y-6 text-[#5D493C]">
                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] mb-1 opacity-70">
                      Artwork ID
                    </div>
                    <div className="font-mono text-sm">
                      SKC-7F3A-9B21
                    </div>
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] mb-1 opacity-70">
                      DID
                    </div>
                    <div className="font-mono text-sm break-all">
                      did:pkh:algo:artisan-13k8f7w
                    </div>
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] mb-1 opacity-70">
                      Provenance
                    </div>
                    <div className="text-sm">
                      Anchored on Algorand & stored on IPFS
                    </div>
                  </div>
                </div>

                {/* Seal */}
                <div className="absolute bottom-10 right-10 w-24 h-24 rounded-full border border-[#B56A3E]/40 flex items-center justify-center">
                  <div className="w-16 h-16 rounded-full border border-[#B56A3E]/30" />
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Scroll Indicator */}
        <motion.div
          animate={{ y: [0, 10, 0] }}
          transition={{ repeat: Infinity, duration: 2 }}
          className="absolute bottom-10 left-1/2 -translate-x-1/2 text-[#8A674F] flex flex-col items-center gap-2"
        >
          <span className="text-xs tracking-[0.3em] uppercase">
            Scroll to Explore
          </span>

          <ChevronDown size={18} />
        </motion.div>
      </section>

      {/* ================= SECOND SECTION ================= */}
      <section className="relative py-32 px-6 border-t border-[#dbc9ad]">
        <div className="max-w-7xl mx-auto grid lg:grid-cols-2 gap-24 items-center">
          {/* LEFT */}
          <div>
            <div className="uppercase tracking-[0.3em] text-xs text-[#9B5E38] mb-6">
              Our Mission
            </div>

            <h2 className="font-serif text-5xl leading-tight mb-10">
              Empowering Artisans.
              <br />
              Protecting Heritage.
            </h2>

            <p className="text-lg leading-relaxed text-[#5C4636] max-w-xl">
              SkillChain combines decentralized identity and tamper-proof
              provenance infrastructure to preserve human craftsmanship across
              generations.
            </p>

            <div className="mt-10 space-y-5">
              {[
                "DID-backed artisan identity",
                "Algorand anchored provenance",
                "IPFS persistent records",
                "Tamper-proof verification",
              ].map((item, i) => (
                <div key={i} className="flex items-center gap-4">
                  <div className="w-2 h-2 rounded-full bg-[#B56A3E]" />
                  <span className="text-[#4E3C31]">{item}</span>
                </div>
              ))}
            </div>
          </div>

          {/* RIGHT IMAGE */}
          <div className="relative">
            <div className="absolute inset-0 rounded-[2rem] border border-[#CDAE86] translate-x-5 translate-y-5" />

            <img
              src="https://images.unsplash.com/photo-1517048676732-d65bc937f952?q=80&w=1200&auto=format&fit=crop"
              alt="artisan"
              className="relative rounded-[2rem] object-cover h-[620px] w-full shadow-2xl"
            />
          </div>
        </div>
      </section>
    </div>
  );
}