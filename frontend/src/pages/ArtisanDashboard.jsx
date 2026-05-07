import React, { useState } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  UserPlus,
  ImagePlus,
  Fingerprint,
  ExternalLink,
  ScrollText,
  ShieldCheck,
  Landmark,
  CheckCircle2,
  Clock3,
  Database,
  LockKeyhole,
  Sparkles,
} from "lucide-react";
import { QRCodeSVG } from "qrcode.react";

import { FileUpload } from "../components/common/FileUpload";
import { CopyButton } from "../components/common/CopyButton";
import { StatusBadge } from "../components/common/StatusBadge";
import { useToast } from "../context/ToastContext";
import * as api from "../api/api";

const steps = [
  {
    title: "Application archived",
    detail: "Your name, craft, and place of practice are recorded in SkillChain's registry.",
    icon: ScrollText,
  },
  {
    title: "Institutional review",
    detail: "An institutional or administrative verifier reviews the artisan record.",
    icon: Landmark,
  },
  {
    title: "DID identity issued",
    detail: "An approved artisan receives a decentralized identity and a permanent provenance anchor.",
    icon: Fingerprint,
  },
  {
    title: "Artwork ownership begins",
    detail: "Registered works can then be anchored to the verified creator identity.",
    icon: ShieldCheck,
  },
];

const trustPillars = [
  {
    title: "Decentralized identity",
    detail: "Every approved artisan receives a DID-backed public record of authorship.",
    icon: Fingerprint,
  },
  {
    title: "Provenance ownership",
    detail: "Future artworks can be linked to the creator who made them, not just the file that represents them.",
    icon: ScrollText,
  },
  {
    title: "Blockchain-backed trust",
    detail: "Anchoring on Algorand preserves a tamper-resistant timeline of authenticity.",
    icon: LockKeyhole,
  },
  {
    title: "Permanent archive",
    detail: "Metadata persistence on IPFS supports durable cultural memory and verification.",
    icon: Database,
  },
];

export const ArtisanDashboard = () => {
  const [artisan, setArtisan] = useState(null);
  const [registered, setRegistered] = useState(false);
  const [form, setForm] = useState({
    name: "",
    craft_type: "",
    cluster: "",
    location: "",
  });
  const [artworkForm, setArtworkForm] = useState({
    title: "",
    description: "",
    materials: "",
  });
  const [artworkFile, setArtworkFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const { data } = await api.registerArtisan(form);
      setArtisan(data);
      setRegistered(true);
      addToast("Artisan record submitted for archival review", "success");
    } catch (err) {
      addToast("Registration failed", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleAddArtwork = async (e) => {
    e.preventDefault();
    if (!artworkFile) return addToast("Please select an artwork file", "error");

    setLoading(true);
    const formData = new FormData();
    formData.append("artwork", artworkFile);
    formData.append("artisan_did", artisan.did);
    formData.append("title", artworkForm.title);
    formData.append("description", artworkForm.description);
    formData.append("materials", artworkForm.materials);

    try {
      const { data } = await api.addArtwork(formData);
      setArtisan((prev) => ({ ...prev, artworks: [...(prev.artworks || []), data] }));
      setArtworkForm({ title: "", description: "", materials: "" });
      setArtworkFile(null);
      addToast("Artwork provenance record created", "success");
    } catch (err) {
      addToast("Failed to add artwork", "error");
    } finally {
      setLoading(false);
    }
  };


  if (!registered) {
    return (
      <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] overflow-hidden">
        <section className="relative px-6 pt-28 pb-20 border-b border-[#d8c7ab] overflow-hidden">
          <div className="absolute inset-0 opacity-[0.05] bg-[url('https://www.transparenttextures.com/patterns/old-map.png')]" />
          <div className="absolute top-[-140px] left-[-120px] w-[420px] h-[420px] rounded-full bg-[#D8B38A]/20 blur-3xl" />
          <div className="absolute bottom-[-160px] right-[-120px] w-[520px] h-[520px] rounded-full bg-[#A85B34]/10 blur-3xl" />

          <div className="relative max-w-7xl mx-auto grid lg:grid-cols-[1.05fr_0.95fr] gap-14 items-center">
            <motion.div
              initial={{ opacity: 0, y: 36 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <div className="flex items-center gap-3 uppercase tracking-[0.32em] text-xs text-[#9A5A38] mb-7">
                <ShieldCheck size={14} />
                Artisan Identity Registry
              </div>

              <h1 className="font-serif text-5xl md:text-7xl leading-[0.94] tracking-[-0.045em] mb-8">
                Your Craft
                <br />
                Deserves Permanent
                <br />
                Trusted Identity.
              </h1>

              <div className="w-28 h-[1px] bg-[#B56A3E] mb-8" />

              <p className="text-xl leading-relaxed text-[#5C4636] max-w-2xl mb-10">
                SkillChain registers artisans, craftspeople, and heritage creators
                into a verified cultural archive where identity, authorship, and
                provenance ownership can endure beyond the marketplace.
              </p>

              <div className="flex flex-wrap gap-4">
                {[
                  "DID-backed identity",
                  "Provenance ownership",
                  "Institutional verification",
                  "Permanent cultural record",
                ].map((item) => (
                  <div
                    key={item}
                    className="px-4 py-2 border border-[#c8b296] rounded-full text-sm tracking-wide bg-[#fffaf1]/65 backdrop-blur-sm"
                  >
                    {item}
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, rotate: 3, y: 28 }}
              animate={{ opacity: 1, rotate: -2, y: 0 }}
              transition={{ duration: 0.95 }}
              className="relative"
            >
              <div className="relative bg-[#E8D9BE] border border-[#d3bea0] shadow-2xl p-8 md:p-10 overflow-hidden">
                <div className="absolute inset-0 opacity-[0.04] bg-[url('https://www.transparenttextures.com/patterns/paper-fibers.png')]" />

                <div className="relative z-10">
                  <div className="flex items-start justify-between mb-8">
                    <div>
                      <div className="uppercase tracking-[0.3em] text-xs text-[#8B694D] mb-3">
                        Registry Purpose
                      </div>
                      <h2 className="font-serif text-3xl leading-tight">
                        A respectful record for living human craftsmanship
                      </h2>
                    </div>

                    <div className="w-14 h-14 rounded-full border border-[#B56A3E]/30 flex items-center justify-center">
                      <Sparkles className="text-[#B56A3E]" size={22} />
                    </div>
                  </div>

                  <div className="space-y-5">
                    {[
                      {
                        icon: Fingerprint,
                        label: "Identity",
                        value: "The artisan is represented as a verified human creator.",
                      },
                      {
                        icon: ScrollText,
                        label: "Ownership",
                        value: "Future works can be tied back to their rightful maker.",
                      },
                      {
                        icon: Landmark,
                        label: "Institutional trust",
                        value: "Approval and legitimacy can be confirmed through trusted issuers.",
                      },
                      {
                        icon: LockKeyhole,
                        label: "Permanence",
                        value: "Authorship is prepared for durable blockchain-backed provenance.",
                      },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="flex items-center justify-between border-b border-[#d5c4a7] pb-4"
                      >
                        <div className="flex items-center gap-4">
                          <item.icon className="text-[#B56A3E]" size={18} />
                          <div>
                            <div className="text-xs uppercase tracking-[0.2em] text-[#8B694D]">
                              {item.label}
                            </div>
                            <div className="text-[#2B1D16] mt-1">{item.value}</div>
                          </div>
                        </div>

                        <CheckCircle2 className="text-emerald-700" size={18} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        <section className="px-6 py-20">
          <div className="max-w-7xl mx-auto grid xl:grid-cols-[1.05fr_0.95fr] gap-8 items-start">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10"
            >
              <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                Registration Form
              </div>
              <h2 className="font-serif text-4xl mb-4">Enter the cultural identity registry</h2>
              <p className="text-[#5C4636] leading-relaxed mb-8 max-w-2xl">
                Register the artisan identity that should be protected, represented,
                and prepared for provenance ownership across future works.
              </p>

              <form onSubmit={handleRegister} className="space-y-6">
                <div>
                  <label className="block text-sm uppercase tracking-[0.18em] text-[#8B694D] mb-2">
                    Artisan Name
                  </label>
                  <input
                    className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                    required
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="Name of the artisan or heritage creator"
                  />
                </div>

                <div className="grid md:grid-cols-2 gap-5">
                  <div>
                    <label className="block text-sm uppercase tracking-[0.18em] text-[#8B694D] mb-2">
                      Craft Tradition
                    </label>
                    <input
                      className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                      required
                      value={form.craft_type}
                      onChange={(e) => setForm({ ...form, craft_type: e.target.value })}
                      placeholder="Banarasi weaving, pottery, embroidery..."
                    />
                  </div>

                  <div>
                    <label className="block text-sm uppercase tracking-[0.18em] text-[#8B694D] mb-2">
                      Cluster / Guild
                    </label>
                    <input
                      className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                      required
                      value={form.cluster}
                      onChange={(e) => setForm({ ...form, cluster: e.target.value })}
                      placeholder="Workshop, collective, cluster, or institution"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm uppercase tracking-[0.18em] text-[#8B694D] mb-2">
                    Place of Practice
                  </label>
                  <input
                    className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                    required
                    value={form.location}
                    onChange={(e) => setForm({ ...form, location: e.target.value })}
                    placeholder="City, district, state, or cultural region"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-[#B56A3E] hover:bg-[#9f5730] transition duration-300 text-white py-5 text-lg tracking-wide shadow-xl disabled:opacity-50 flex items-center justify-center gap-3"
                >
                  <UserPlus size={18} />
                  {loading ? "Submitting identity record..." : "Submit Artisan Record"}
                </button>
              </form>
            </motion.div>

            <div className="space-y-8">
              <motion.div
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8"
              >
                <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                  DID Identity
                </div>
                <h3 className="font-serif text-3xl mb-4">What this registration creates</h3>
                <p className="text-[#5C4636] leading-relaxed">
                  Approval creates a decentralized identity for the artisan. That DID
                  becomes the public authorship layer through which future artworks and
                  records can be verified as belonging to a real human maker.
                </p>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8"
              >
                <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                  Provenance Ownership
                </div>
                <p className="text-[#5C4636] leading-relaxed">
                  This is not just a profile. It is the foundation for ownership of
                  provenance, so every future registration can point back to the creator
                  who made the work and the tradition from which it came.
                </p>
              </motion.div>
            </div>
          </div>
        </section>

        <section className="px-6 pb-20">
          <div className="max-w-7xl mx-auto grid lg:grid-cols-2 gap-8">
            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
              <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                Trust Indicators
              </div>
              <h3 className="font-serif text-3xl mb-8">Why the registry is trustworthy</h3>

              <div className="space-y-5">
                {trustPillars.map((item) => (
                  <div
                    key={item.title}
                    className="flex items-start gap-4 border-b border-[#d9c7ac] pb-4"
                  >
                    <div className="w-11 h-11 rounded-full border border-[#B56A3E]/30 flex items-center justify-center shrink-0">
                      <item.icon className="text-[#B56A3E]" size={18} />
                    </div>
                    <div>
                      <div className="font-medium text-lg mb-1">{item.title}</div>
                      <p className="text-[#5C4636] leading-relaxed">{item.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
              <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                What Happens Next
              </div>
              <h3 className="font-serif text-3xl mb-8">From registration to verified authorship</h3>

              <div className="space-y-6">
                {steps.map((step, index) => (
                  <div key={step.title} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="w-11 h-11 rounded-full border border-[#B56A3E]/30 flex items-center justify-center text-[#B56A3E]">
                        <step.icon size={18} />
                      </div>
                      {index < steps.length - 1 && (
                        <div className="w-px flex-1 bg-[#d8c7ab] mt-3" />
                      )}
                    </div>

                    <div className="pt-1 pb-3">
                      <div className="font-medium text-lg mb-1">{step.title}</div>
                      <p className="text-[#5C4636] leading-relaxed">{step.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="px-6 pb-24">
          <div className="max-w-7xl mx-auto bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
            <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
              Institutional References
            </div>
            <h3 className="font-serif text-3xl mb-4">Built for institutions onboarding real artisans</h3>
            <p className="text-[#5C4636] max-w-4xl leading-relaxed">
              SkillChain is designed for cultural organizations, heritage programs,
              artisan collectives, and institutions that need a respectful and verifiable
              way to register the creators they represent. The artisan is not reduced to
              a user account. They are entered into a durable trust infrastructure.
            </p>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] px-6 py-12">
      <div className="max-w-7xl mx-auto">
        <div className="grid md:grid-cols-3 gap-6 mb-10">
          <div className="md:col-span-2 bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
            <div className="flex items-center gap-3 mb-5">
              <Fingerprint className="text-[#B56A3E]" size={24} />
              <h2 className="text-3xl font-serif">Artisan Registry Record</h2>
              <StatusBadge status="pending" text="Pending Review" />
            </div>

            <p className="text-[#5C4636] leading-relaxed mb-6 max-w-2xl">
              The artisan identity has been entered into the registry and is now
              awaiting institutional approval before a DID and provenance-ready trust
              record are fully activated.
            </p>

            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                <Clock3 className="text-[#B56A3E]" size={18} />
                <span className="text-sm uppercase tracking-[0.18em] text-[#8B694D] w-28">
                  Status
                </span>
                <span className="font-medium">Awaiting institutional verification</span>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D] mb-1">
                    Artisan Name
                  </div>
                  <div className="text-lg font-medium">{artisan.name}</div>
                </div>

                <div className="p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D] mb-1">
                    Craft Tradition
                  </div>
                  <div className="text-lg font-medium">{artisan.craft_type}</div>
                </div>

                <div className="p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D] mb-1">
                    Cluster / Guild
                  </div>
                  <div className="text-lg font-medium">{artisan.cluster}</div>
                </div>

                <div className="p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D] mb-1">
                    Place of Practice
                  </div>
                  <div className="text-lg font-medium">{artisan.location}</div>
                </div>
              </div>

              {artisan.artisan_id && (
                <div className="flex items-center gap-3 p-4 bg-[#fffaf1] border border-[#d8c6aa]">
                  <span className="text-sm uppercase tracking-[0.18em] text-[#8B694D] w-28">
                    Registry ID
                  </span>
                  <code className="flex-1 font-mono text-sm break-all">{artisan.artisan_id}</code>
                  <CopyButton text={artisan.artisan_id} label="Registry ID" />
                </div>
              )}
            </div>
          </div>

          <div className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 flex flex-col justify-between">
            <div>
              <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                Registry Note
              </div>
              <h3 className="font-serif text-3xl mb-4">Identity is issued after review</h3>
              <p className="text-[#5C4636] leading-relaxed">
                Once approved, this artisan record will receive a DID, a wallet-backed
                trust identity, and the ability to anchor artworks as verified works of origin.
              </p>
            </div>

            <div className="mt-8 p-5 border border-[#d5c4a7] bg-[#f5ebdd]">
              <div className="uppercase tracking-[0.2em] text-xs text-[#8B694D] mb-2">
                Approval prepares
              </div>
              <div className="space-y-2 text-[#5C4636]">
                <div>DID identity issuance</div>
                <div>Creator-authored provenance records</div>
                <div>Blockchain-linked authenticity</div>
              </div>
            </div>
          </div>
        </div>

        {artisan.did ? (
          <>
            <div className="grid md:grid-cols-3 gap-6 mb-10">
              <div className="md:col-span-2 bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
                <div className="flex items-center gap-3 mb-4">
                  <Fingerprint className="text-[#B56A3E]" size={24} />
                  <h2 className="text-2xl font-serif">Verified Identity</h2>
                  <StatusBadge status="verified" text="Approved" />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center gap-3 p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                    <span className="text-sm text-[#8B694D] w-20">DID</span>
                    <code className="flex-1 font-mono text-sm truncate">{artisan.did}</code>
                    <CopyButton text={artisan.did} label="DID" />
                  </div>
                </div>
              </div>

              <div className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 flex flex-col items-center justify-center">
                <div className="p-3 bg-white shadow-sm">
                  <QRCodeSVG value={`http://localhost:5173/verify?did=${artisan.did}`} size={160} level="H" />
                </div>
                <p className="text-xs text-[#8B694D] mt-4 text-center uppercase tracking-[0.18em]">
                  Scan to verify identity
                </p>
              </div>
            </div>

            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10 mb-10">
              <h3 className="text-2xl font-serif mb-5 flex items-center gap-2">
                <ImagePlus size={20} className="text-[#B56A3E]" /> Register Artwork Provenance
              </h3>

              <form onSubmit={handleAddArtwork} className="space-y-5">
                <FileUpload
                  onFileSelect={setArtworkFile}
                  accept="image/*"
                  label="Upload artwork image"
                  sublabel="Register a work to this verified artisan identity"
                />

                <div className="grid md:grid-cols-2 gap-4">
                  <input
                    className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                    placeholder="Artwork title"
                    required
                    value={artworkForm.title}
                    onChange={(e) => setArtworkForm({ ...artworkForm, title: e.target.value })}
                  />
                  <input
                    className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                    placeholder="Materials used"
                    value={artworkForm.materials}
                    onChange={(e) => setArtworkForm({ ...artworkForm, materials: e.target.value })}
                  />
                </div>

                <textarea
                  className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                  rows={4}
                  placeholder="Describe the work, its process, and its cultural significance..."
                  value={artworkForm.description}
                  onChange={(e) => setArtworkForm({ ...artworkForm, description: e.target.value })}
                />

                <button
                  type="submit"
                  disabled={loading}
                  className="bg-[#B56A3E] hover:bg-[#9f5730] transition duration-300 text-white py-4 px-6 tracking-wide shadow-xl disabled:opacity-50 flex items-center gap-3"
                >
                  <ImagePlus size={18} /> Create Provenance Record
                </button>
              </form>
            </div>

            <h3 className="text-2xl font-serif mb-6">Registered Works</h3>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              <AnimatePresence>
                {(artisan.artworks || []).map((art, i) => (
                  <motion.div
                    key={art.ipfs_cid || i}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0 }}
                    className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] overflow-hidden"
                  >
                    <div className="aspect-square bg-[#eadcc5] relative overflow-hidden">
                      {art.image_url ? (
                        <img src={art.image_url} alt={art.title} className="w-full h-full object-cover" />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center text-[#8B694D]">
                          Artwork preview
                        </div>
                      )}
                    </div>
                    <div className="p-5">
                      <h4 className="font-serif text-xl mb-1">{art.title}</h4>
                      <p className="text-sm text-[#6D5646] line-clamp-2 mb-3">{art.description}</p>

                      {art.artwork_id ? (
                        <Link
                          to={`/artworks/${art.artwork_id}`}
                          className="block w-full text-center mb-4 bg-[#1C1A16] hover:bg-black transition duration-300 text-[#F7F0E1] py-3 px-4 tracking-wide shadow-xl"
                        >
                          View Provenance Object
                        </Link>
                      ) : (
                        <div className="w-full mb-4 text-xs text-[#8B694D] p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                          This work is missing an internal id. Re-register to enable collector acquisition.
                        </div>
                      )}

                      <div className="space-y-2 text-xs">
                        <div className="flex items-center justify-between p-2 bg-[#fffaf1] border border-[#d8c6aa]">
                          <span className="text-[#8B694D]">IPFS CID</span>
                          <div className="flex items-center gap-1 font-mono">
                            {art.ipfs_cid?.slice(0, 12)}... <CopyButton text={art.ipfs_cid} />
                          </div>
                        </div>
                        <div className="flex items-center justify-between p-2 bg-[#fffaf1] border border-[#d8c6aa]">
                          <span className="text-[#8B694D]">Txn ID</span>
                          <a
                            href={`https://algoexplorer.io/tx/${art.txn_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 text-[#B56A3E] hover:underline"
                          >
                            View <ExternalLink size={12} />
                          </a>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>

              {(artisan.artworks || []).length === 0 && (
                <div className="col-span-full text-center py-12 text-[#8B694D] bg-[#F7F0E1]/85 border border-dashed border-[#d8c6aa]">
                  No artworks registered yet. Once approved, add the first work to this artisan identity.
                </div>
              )}
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
};
