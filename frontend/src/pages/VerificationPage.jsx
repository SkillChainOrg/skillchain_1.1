import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  ExternalLink,
  FileCheck2,
  Database,
  Fingerprint,
  LockKeyhole,
  ScrollText,
  Sparkles,
  Landmark,
  Image as ImageIcon,
  ScanSearch,
} from "lucide-react";

import { FileUpload } from "../components/common/FileUpload";
import { CopyButton } from "../components/common/CopyButton";
import { useToast } from "../context/ToastContext";
import * as api from "../api/api";

const formatDate = (value) => {
  if (!value) return "Not available";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("en-IN", {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
};

const shorten = (value, start = 14, end = 8) => {
  if (!value) return "";
  if (value.length <= start + end + 3) return value;
  return `${value.slice(0, start)}...${value.slice(-end)}`;
};

const normalizeResult = (data) => {
  const verified = Boolean(data?.verified ?? data?.valid);
  const artistName = data?.artisan || data?.artist_name || data?.issued_by || "";
  const artistDid = data?.artisan_did || data?.identity_did || data?.issuer_did || "";
  const issuerName = data?.issuer || data?.institution || "";

  return {
    ...data,
    verified,
    artistName,
    artistDid,
    issuerName,
  };
};

export const VerificationPage = () => {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  useEffect(() => {
    if (!file || file.type === "application/pdf") {
      setPreviewUrl("");
      return undefined;
    }

    const url = URL.createObjectURL(file);
    setPreviewUrl(url);

    return () => URL.revokeObjectURL(url);
  }, [file]);

  const handleVerify = async (e) => {
    e.preventDefault();

    if (!file) {
      addToast("Upload an artwork or certificate to begin verification", "error");
      return;
    }

    setLoading(true);
    setResult(null);

    const formData = new FormData();
    formData.append("certificate", file);

    try {
      const { data } = await api.verifyCertificate(formData);
      const normalized = normalizeResult(data);

      setResult(normalized);

      addToast(
        normalized.verified
          ? "Authenticity confirmed and identity record uncovered"
          : "We could not confirm provenance for this upload",
        normalized.verified ? "success" : "error"
      );
    } catch (err) {
      addToast("Verification error occurred", "error");
    } finally {
      setLoading(false);
    }
  };

  const artistLabel = result?.artistName || "Verified creator record unavailable";
  const artistDid = result?.artistDid || "";
  const trustGrade = result?.trust_grade || (result?.verified ? "A" : "Unverified");

  const provenanceSteps = [
    {
      icon: FileCheck2,
      title: "Artifact hash matched",
      detail: result?.verified
        ? "The uploaded work matched its registered fingerprint."
        : "The submitted file could not be matched to a trusted record.",
      active: Boolean(result?.verified),
    },
    {
      icon: Fingerprint,
      title: "Creator identity resolved",
      detail: artistDid
        ? "A DID-backed identity record was recovered for this creator."
        : "No public artisan identity was resolved from the provenance record.",
      active: Boolean(artistDid),
    },
    {
      icon: LockKeyhole,
      title: "Blockchain anchored",
      detail: result?.tx_id
        ? `Anchored on Algorand in round ${result.confirmed_round || "confirmed"}.`
        : "No blockchain anchor could be confirmed for this upload.",
      active: Boolean(result?.tx_id),
    },
    {
      icon: Database,
      title: "IPFS persistence confirmed",
      detail: result?.ipfs_cid
        ? "Metadata persisted to decentralized storage for long-term auditability."
        : "No decentralized storage record was available.",
      active: Boolean(result?.ipfs_cid),
    },
  ];

  const trustPillars = [
    {
      label: "Tamper-proof integrity",
      value: result?.hmac_valid ? "Confirmed" : result ? "Unavailable" : "Pending",
    },
    {
      label: "Provenance signature",
      value: result?.signature_valid ? "Valid" : result ? "Unavailable" : "Pending",
    },
    {
      label: "Cultural record type",
      value: result?.doc_type ? result.doc_type : "Artifact / certificate",
    },
    {
      label: "Institutional issuer",
      value: result?.issuerName || "Not disclosed",
    },
  ];

  return (
    <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] overflow-hidden">
      <section className="relative px-6 pt-28 pb-24 border-b border-[#d8c7ab] overflow-hidden">
        <div className="absolute inset-0 opacity-[0.05] bg-[url('https://www.transparenttextures.com/patterns/old-map.png')]" />
        <div className="absolute top-[-120px] left-[-90px] w-[380px] h-[380px] rounded-full bg-[#D8B38A]/20 blur-3xl" />
        <div className="absolute right-[-110px] bottom-[-180px] w-[520px] h-[520px] rounded-full bg-[#A85B34]/10 blur-3xl" />

        <div className="relative max-w-7xl mx-auto grid lg:grid-cols-[1.15fr_0.85fr] gap-16 items-center">
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex items-center gap-3 uppercase tracking-[0.32em] text-xs text-[#9A5A38] mb-7">
              <ShieldCheck size={14} />
              Provenance & Identity Verification
            </div>

            <h1 className="font-serif text-5xl md:text-7xl leading-[0.93] tracking-[-0.045em] mb-8">
              Reveal the Human
              <br />
              Behind the Work.
            </h1>

            <div className="w-28 h-[1px] bg-[#B56A3E] mb-8" />

            <p className="text-xl leading-relaxed text-[#5C4636] max-w-2xl mb-10">
              SkillChain verifies artwork, certificates, and cultural records by
              tracing authenticity back to a real creator identity, an anchored
              provenance trail, and a durable trust record.
            </p>

            <div className="flex flex-wrap gap-4">
              {[
                "DID-backed artisan identity",
                "Algorand anchored provenance",
                "IPFS persistence",
                "Institutional trust",
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
            initial={{ opacity: 0, rotate: 3, y: 32 }}
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
                      Verification Record
                    </div>
                    <h2 className="font-serif text-3xl leading-tight">
                      Museum-grade trust for living creators
                    </h2>
                  </div>

                  <div className="w-14 h-14 rounded-full border border-[#B56A3E]/30 flex items-center justify-center">
                    <Sparkles className="text-[#B56A3E]" size={22} />
                  </div>
                </div>

                <div className="space-y-5">
                  {[
                    {
                      icon: ImageIcon,
                      label: "Artifact Review",
                      value: "Artwork and certificate-aware verification",
                    },
                    {
                      icon: Fingerprint,
                      label: "Identity Reveal",
                      value: "DID-linked artisan authenticity",
                    },
                    {
                      icon: ScrollText,
                      label: "Provenance Trail",
                      value: "Chronology of custody and issuance",
                    },
                    {
                      icon: Landmark,
                      label: "Institutional Trust",
                      value: "Anchored where institutions participate",
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

      <section className="relative px-6 py-24">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-14">
            <div className="uppercase tracking-[0.3em] text-xs text-[#9A5A38] mb-5">
              Verification Portal
            </div>
            <h2 className="font-serif text-5xl mb-6">Uncover a Provenance Record</h2>
            <p className="text-lg text-[#5C4636] max-w-3xl mx-auto leading-relaxed">
              Upload an artwork image, certificate, or archival record. SkillChain
              will validate authenticity, trace its provenance, and reveal the
              verified identity attached to that cultural artifact.
            </p>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="grid lg:grid-cols-[1.1fr_0.9fr] gap-8 bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] backdrop-blur-sm p-8 md:p-12"
          >
            <div>
              <form onSubmit={handleVerify} className="space-y-8">
                <FileUpload
                  onFileSelect={setFile}
                  accept=".pdf,.jpg,.jpeg,.png,.webp"
                  label="Drop artwork, certificate, or provenance image"
                  sublabel="Museum record, artisan certificate, or registered artwork"
                />

                <button
                  type="submit"
                  disabled={loading || !file}
                  className="w-full bg-[#B56A3E] hover:bg-[#9f5730] transition duration-300 text-white py-5 text-lg tracking-wide shadow-xl disabled:opacity-50"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-3">
                      <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Verifying provenance...
                    </span>
                  ) : (
                    <span className="flex items-center justify-center gap-3">
                      <ScanSearch size={20} />
                      Verify Authenticity
                    </span>
                  )}
                </button>
              </form>
            </div>

            <div className="relative bg-[#EDE0C7] border border-[#d5bf9c] min-h-[360px] p-6 overflow-hidden">
              <div className="absolute inset-0 opacity-[0.04] bg-[url('https://www.transparenttextures.com/patterns/paper-fibers.png')]" />

              <div className="relative z-10 h-full flex flex-col">
                <div className="uppercase tracking-[0.26em] text-xs text-[#8B694D] mb-4">
                  Artifact Preview
                </div>

                <div className="flex-1 border border-[#cdb693] bg-[#f8f1e5] flex items-center justify-center overflow-hidden">
                  {previewUrl ? (
                    <img
                      src={previewUrl}
                      alt="Uploaded artwork preview"
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <div className="text-center px-8">
                      <ImageIcon className="mx-auto text-[#9A5A38] mb-4" size={34} />
                      <p className="font-serif text-2xl mb-3">Awaiting artifact</p>
                      <p className="text-[#6D5646] leading-relaxed">
                        Your uploaded work will appear here before its creator
                        record and provenance trail are revealed.
                      </p>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-4 mt-5 text-sm text-[#5C4636]">
                  <div>
                    <div className="uppercase tracking-[0.2em] text-xs text-[#8B694D] mb-1">
                      File
                    </div>
                    <div className="truncate">{file?.name || "No upload yet"}</div>
                  </div>
                  <div>
                    <div className="uppercase tracking-[0.2em] text-xs text-[#8B694D] mb-1">
                      Type
                    </div>
                    <div>{file?.type || "Artwork / certificate record"}</div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          <AnimatePresence>
            {result && (
              <motion.div
                initial={{ opacity: 0, y: 32 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 12 }}
                className="mt-14 space-y-8"
              >
                <div className="grid lg:grid-cols-[0.72fr_1.28fr] gap-8">
                  <div className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8">
                    <div className="flex justify-center mb-8">
                      <motion.div
                        initial={{ scale: 0.8, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ type: "spring", stiffness: 140 }}
                        className={`w-36 h-36 rounded-full border flex flex-col items-center justify-center shadow-xl ${
                          result.verified
                            ? "border-emerald-700 bg-emerald-700/5 text-emerald-700"
                            : "border-red-700 bg-red-700/5 text-red-700"
                        }`}
                      >
                        {result.verified ? <CheckCircle2 size={42} /> : <XCircle size={42} />}
                        <span className="uppercase tracking-[0.22em] text-xs mt-3 text-center px-4">
                          {result.verified ? "Authenticity Confirmed" : "Record Not Confirmed"}
                        </span>
                      </motion.div>
                    </div>

                    <div className="text-center mb-8">
                      <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-3">
                        Verification Status
                      </div>
                      <h3 className="font-serif text-4xl leading-tight">
                        {result.verified ? "Creator record uncovered" : "Provenance could not be established"}
                      </h3>
                    </div>

                    <div className="space-y-4 border-t border-[#d5c4a7] pt-6">
                      <div className="flex items-center justify-between">
                        <span className="uppercase tracking-[0.2em] text-xs text-[#8B694D]">
                          Trust Grade
                        </span>
                        <span className="text-lg font-medium">{trustGrade}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="uppercase tracking-[0.2em] text-xs text-[#8B694D]">
                          Trust Score
                        </span>
                        <span className="text-lg font-medium">
                          {result.trust_score ?? (result.verified ? "Verified" : "Unavailable")}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="uppercase tracking-[0.2em] text-xs text-[#8B694D]">
                          Record Date
                        </span>
                        <span className="text-right">{formatDate(result.issued_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-3">
                          Identity Reveal
                        </div>
                        <h3 className="font-serif text-4xl leading-tight">
                          This work belongs to a real verified creator
                        </h3>
                      </div>

                      <ShieldCheck
                        className={result.verified ? "text-emerald-700" : "text-red-700"}
                        size={36}
                      />
                    </div>

                    <div className="grid md:grid-cols-[0.9fr_1.1fr] gap-6">
                      <div className="bg-[#EDE0C7] border border-[#d2b998] p-6">
                        <div className="w-14 h-14 rounded-full border border-[#B56A3E]/30 flex items-center justify-center mb-5">
                          <Fingerprint className="text-[#B56A3E]" size={22} />
                        </div>

                        <div className="uppercase tracking-[0.22em] text-xs text-[#8B694D] mb-2">
                          Verified Artist Identity
                        </div>
                        <div className="font-serif text-3xl leading-tight mb-4">
                          {result.verified ? artistLabel : "Identity unavailable"}
                        </div>

                        <div className="space-y-3 text-sm text-[#5C4636]">
                          <div>
                            <div className="uppercase tracking-[0.2em] text-xs text-[#8B694D] mb-1">
                              DID
                            </div>
                            <div className="break-all">{artistDid || "No DID resolved"}</div>
                          </div>

                          <div>
                            <div className="uppercase tracking-[0.2em] text-xs text-[#8B694D] mb-1">
                              Record Type
                            </div>
                            <div>{result.doc_type || "Registered cultural artifact"}</div>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-4">
                        {trustPillars.map((item) => (
                          <div
                            key={item.label}
                            className="flex items-center justify-between border-b border-[#d9c7ac] pb-4"
                          >
                            <div>
                              <div className="uppercase text-xs tracking-[0.2em] text-[#8B694D] mb-1">
                                {item.label}
                              </div>
                              <div className="text-lg">{item.value}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="grid lg:grid-cols-[1fr_1fr] gap-8">
                  <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10">
                    <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                      Provenance Timeline
                    </div>
                    <h3 className="font-serif text-3xl mb-8">How authenticity was established</h3>

                    <div className="space-y-6">
                      {provenanceSteps.map((step, index) => (
                        <div key={step.title} className="flex gap-4">
                          <div className="flex flex-col items-center">
                            <div
                              className={`w-11 h-11 rounded-full border flex items-center justify-center ${
                                step.active
                                  ? "border-emerald-700 bg-emerald-700/5 text-emerald-700"
                                  : "border-[#c9b594] text-[#9A5A38]"
                              }`}
                            >
                              <step.icon size={18} />
                            </div>
                            {index < provenanceSteps.length - 1 && (
                              <div className="w-px flex-1 bg-[#d8c7ab] mt-3" />
                            )}
                          </div>

                          <div className="pt-1 pb-4">
                            <div className="font-medium text-lg mb-1">{step.title}</div>
                            <p className="text-[#5C4636] leading-relaxed">{step.detail}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-[#E8D9BE] border border-[#d3bea0] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 md:p-10 overflow-hidden">
                    <div className="uppercase tracking-[0.28em] text-xs text-[#9A5A38] mb-4">
                      Anchoring & Persistence
                    </div>
                    <h3 className="font-serif text-3xl mb-8">Durable trust record</h3>

                    <div className="space-y-5">
                      {result.tx_id && (
                        <div className="flex items-center justify-between border-b border-[#d5c4a7] pb-5 gap-5">
                          <div>
                            <div className="uppercase text-xs tracking-[0.2em] text-[#8B694D] mb-1">
                              Algorand Anchor
                            </div>
                            <div className="font-mono text-sm break-all">{shorten(result.tx_id, 20, 10)}</div>
                          </div>

                          <a
                            href={result.explorer_url || `https://testnet.explorer.perawallet.app/tx/${result.tx_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 text-[#B56A3E] hover:underline shrink-0"
                          >
                            View on chain
                            <ExternalLink size={16} />
                          </a>
                        </div>
                      )}

                      {result.ipfs_cid && (
                        <div className="flex items-center justify-between border-b border-[#d5c4a7] pb-5 gap-5">
                          <div>
                            <div className="uppercase text-xs tracking-[0.2em] text-[#8B694D] mb-1">
                              IPFS Persistence
                            </div>
                            <div className="font-mono text-sm break-all">{shorten(result.ipfs_cid, 24, 10)}</div>
                          </div>
                          <CopyButton text={result.ipfs_cid} label="IPFS CID" />
                        </div>
                      )}

                      {artistDid && (
                        <div className="flex items-center justify-between border-b border-[#d5c4a7] pb-5 gap-5">
                          <div>
                            <div className="uppercase text-xs tracking-[0.2em] text-[#8B694D] mb-1">
                              DID Identity
                            </div>
                            <div className="font-mono text-sm break-all">{shorten(artistDid, 24, 10)}</div>
                          </div>
                          <CopyButton text={artistDid} label="DID" />
                        </div>
                      )}

                      <div className="flex items-center justify-between gap-5">
                        <div>
                          <div className="uppercase text-xs tracking-[0.2em] text-[#8B694D] mb-1">
                            Integrity Confirmation
                          </div>
                          <div className="text-lg">
                            {result.hmac_valid || result.signature_valid
                              ? "Tamper-proof evidence confirmed"
                              : "Integrity evidence unavailable"}
                          </div>
                        </div>

                        <div
                          className={`px-4 py-2 border rounded-full text-sm ${
                            result.hmac_valid || result.signature_valid
                              ? "border-emerald-700/30 text-emerald-700 bg-emerald-700/5"
                              : "border-[#c9b594] text-[#7a6557] bg-[#f5ebdd]"
                          }`}
                        >
                          {result.hmac_valid || result.signature_valid ? "Confirmed" : "Pending"}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {!result.verified && (
                  <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-8 text-center">
                    <XCircle className="mx-auto text-red-700 mb-4" size={42} />
                    <h3 className="font-serif text-3xl mb-3">This upload could not be connected to a trusted provenance record</h3>
                    <p className="text-[#5C4636] max-w-3xl mx-auto leading-relaxed">
                      The file may have been altered, corrupted, or never registered through
                      SkillChain&apos;s cultural trust infrastructure. Without a matching
                      provenance trail, we cannot reveal a verified creator identity.
                    </p>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </section>
    </div>
  );
};
