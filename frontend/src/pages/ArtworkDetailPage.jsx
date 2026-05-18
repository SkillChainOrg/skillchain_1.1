import React, { useEffect, useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ShieldCheck, Fingerprint, ScrollText, ExternalLink, Wallet } from "lucide-react";
import algosdk from "algosdk";
import { PeraWalletConnect } from "@perawallet/connect";
import * as api from "../api/api";
import { useToast } from "../context/ToastContext";

const peraWallet = new PeraWalletConnect({ shouldShowSignTxnToast: false });
const algodClient = new algosdk.Algodv2(
  "",
  import.meta.env.VITE_ALGOD_URL || "https://testnet-api.algonode.cloud",
  ""
);
const stringAbiType = algosdk.ABIType.from("string");
const acquireMethod = new algosdk.ABIMethod({
  name: "acquire",
  args: [{ type: "string", name: "artwork_id" }],
  returns: { type: "bool" },
});
const textEncoder = new TextEncoder();

const getErrorMessage = (error, fallback) =>
  error?.response?.data?.reason ||
  error?.response?.data?.error ||
  error?.message ||
  fallback;

const connectPeraWallet = async () => {
  const reconnected = await peraWallet.reconnectSession();
  if (Array.isArray(reconnected) && reconnected[0]) return reconnected[0];
  const accounts = await peraWallet.connect();
  return accounts?.[0];
};

const buildGroupedTransactions = async ({ challenge, walletAddress }) => {
  const suggestedParams = await algodClient.getTransactionParams().do();
  const artworkId = String(challenge.artwork_id);
  const paymentTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: walletAddress,
    receiver: challenge.receiver,
    amount: Number(challenge.amount),
    suggestedParams,
  });

  const appCallTxn = algosdk.makeApplicationNoOpTxnFromObject({
    sender: walletAddress,
    appIndex: Number(challenge.app_id),
    suggestedParams: {
      ...suggestedParams,
      fee: suggestedParams.minFee,
      flatFee: true,
    },
    appArgs: [
      acquireMethod.getSelector(),
      stringAbiType.encode(artworkId),
    ],
    boxes: (challenge.boxes || []).map((box) => ({
      appIndex: 0,
      name: textEncoder.encode(box.name),
    })),
  });

  algosdk.assignGroupID([paymentTxn, appCallTxn]);
  return { paymentTxn, appCallTxn };
};

const signAndSubmitGroup = async ({ paymentTxn, appCallTxn, walletAddress }) => {
  const txGroups = [[paymentTxn, appCallTxn].map((txn) => ({ txn, signers: [walletAddress] }))];
  const signedGroup = await peraWallet.signTransaction(txGroups);
  await algodClient.sendRawTransaction(signedGroup).do();
  const appCallTxId = appCallTxn.txID();
  await algosdk.waitForConfirmation(algodClient, appCallTxId, 4);
  return {
    appCallTxId,
    paymentTxId: paymentTxn.txID(),
  };
};

export const ArtworkDetailPage = () => {
  const { artworkId } = useParams();
  const { addToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [artwork, setArtwork] = useState(null);
  const [provenance, setProvenance] = useState([]);
  const [ownership, setOwnership] = useState(null);
  const [collector, setCollector] = useState({ name: "", email: "" });
  const [acquiring, setAcquiring] = useState(false);
  const [walletAddress, setWalletAddress] = useState("");
  const [settlementInfo, setSettlementInfo] = useState(null);

  const id = useMemo(() => Number(artworkId), [artworkId]);

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      try {
        setLoading(true);
        const { data } = await api.getArtwork(id);
        if (!mounted) return;
        setArtwork(data.artwork);
        setProvenance(data.provenance_events || []);
        setOwnership(data.ownership || null);
      } catch {
        addToast("Could not load artwork record", "error");
      } finally {
        if (mounted) setLoading(false);
      }
    };

    if (Number.isFinite(id)) run();
    return () => {
      mounted = false;
    };
  }, [id, addToast]);

  const refreshArtwork = async () => {
    const { data } = await api.getArtwork(id);
    setArtwork(data.artwork);
    setProvenance(data.provenance_events || []);
    setOwnership(data.ownership || null);
  };

  const handleAcquire = async () => {
    try {
      if (!collector.name.trim() || !collector.email.trim()) {
        addToast("Collector name and email are required to record acquisition", "error");
        return;
      }

      setAcquiring(true);
      setSettlementInfo(null);

      let challenge;
      try {
        await api.acquireArtwork({
          artwork_id: id,
          collector_name: collector.name,
          collector_email: collector.email,
        });
        addToast("Expected a 402 payment challenge but received a direct success response", "error");
        return;
      } catch (error) {
        if (error?.response?.status !== 402) {
          throw error;
        }
        challenge = error.response.data?.payment_requirements;
      }

      if (!challenge) {
        throw new Error("Missing x402 payment challenge");
      }

      const connectedWallet = await connectPeraWallet();
      if (!connectedWallet) {
        throw new Error("Pera Wallet did not return an address");
      }
      setWalletAddress(connectedWallet);

      const { paymentTxn, appCallTxn } = await buildGroupedTransactions({
        challenge,
        walletAddress: connectedWallet,
      });

      const { appCallTxId, paymentTxId } = await signAndSubmitGroup({
        paymentTxn,
        appCallTxn,
        walletAddress: connectedWallet,
      });

      const verification = await api.acquireArtwork({
        artwork_id: id,
        collector_name: collector.name,
        collector_email: collector.email,
        wallet_address: connectedWallet,
        tx_id: appCallTxId,
        challenge_nonce: challenge.challenge_nonce,
      });

      setSettlementInfo({
        ...verification.data?.settlement,
        explorer_url: verification.data?.explorer_url,
        payment_tx_id: paymentTxId,
      });
      addToast("Acquisition settled on Algorand Testnet", "success");
      await refreshArtwork();
    } catch (error) {
      addToast(getErrorMessage(error, "Acquisition flow failed"), "error");
    } finally {
      setAcquiring(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] px-6 pt-24">
        <div className="max-w-5xl mx-auto text-[#6D5646]">Preparing provenance object...</div>
      </div>
    );
  }

  if (!artwork) {
    return (
      <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] px-6 pt-24">
        <div className="max-w-5xl mx-auto">
          <p className="text-[#6D5646]">This artwork record could not be resolved.</p>
          <Link to="/verify" className="text-[#B56A3E] hover:underline">
            Return to verification
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F0E7D3] text-[#2B1D16] overflow-hidden">
      <section className="relative px-6 pt-24 pb-10 border-b border-[#d8c7ab] overflow-hidden">
        <div className="absolute inset-0 opacity-[0.05] bg-[url('https://www.transparenttextures.com/patterns/old-map.png')]" />
        <div className="relative max-w-6xl mx-auto grid lg:grid-cols-[1.1fr_0.9fr] gap-10">
          <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] overflow-hidden">
            <div className="aspect-[4/3] bg-[#eadcc5] flex items-center justify-center text-[#8B694D]">
              Artwork preview
            </div>
            <div className="p-7">
              <h1 className="text-4xl font-serif mb-2">{artwork.title || "Untitled work"}</h1>
              <p className="text-[#6D5646] mb-4">
                {artwork.description || "A recorded work in the SkillChain archive."}
              </p>
              <div className="grid sm:grid-cols-2 gap-3 text-sm">
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <Fingerprint size={14} /> Artist DID
                  </div>
                  <div className="mt-2 font-mono break-all text-xs">{artwork.artisan_did}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ShieldCheck size={14} /> Status
                  </div>
                  <div className="mt-2">{artwork.status || "archived"}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ScrollText size={14} /> IPFS CID
                  </div>
                  <div className="mt-2 font-mono break-all text-xs">{artwork.ipfs_cid || "-"}</div>
                </div>
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                  <div className="flex items-center gap-2 text-[#8B694D] uppercase tracking-[0.18em] text-xs">
                    <ExternalLink size={14} /> Chain Anchor
                  </div>
                  {artwork.tx_id ? (
                    <a
                      className="mt-2 inline-flex items-center gap-1 text-[#B56A3E] hover:underline"
                      href={`https://testnet.explorer.perawallet.app/tx/${artwork.tx_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View transaction <ExternalLink size={12} />
                    </a>
                  ) : (
                    <div className="mt-2">-</div>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-7">
              <h2 className="text-2xl font-serif mb-2">Acquire Artwork</h2>
              <p className="text-sm text-[#6D5646] mb-4">
                SkillChain now settles acquisition with an Algorand Testnet payment grouped atomically with the marketplace contract ownership update.
              </p>
              {ownership?.owner_name ? (
                <div className="p-3 bg-[#fffaf1] border border-[#d8c6aa] text-sm text-[#6D5646] mb-4">
                  Current ownership snapshot: <span className="text-[#2B1D16]">{ownership.owner_name}</span>
                  {ownership.owner_wallet ? (
                    <span className="block mt-1 font-mono text-xs text-[#8B694D]">{ownership.owner_wallet}</span>
                  ) : null}
                </div>
              ) : null}
              {walletAddress ? (
                <div className="mb-4 p-3 bg-[#1C1A16] text-[#F7F0E1] text-xs tracking-[0.12em] uppercase flex items-center gap-2">
                  <Wallet size={14} />
                  Connected wallet: <span className="font-mono normal-case">{walletAddress}</span>
                </div>
              ) : null}
              <div className="grid gap-3">
                <input
                  className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                  placeholder="Collector name"
                  value={collector.name}
                  onChange={(e) => setCollector((c) => ({ ...c, name: e.target.value }))}
                />
                <input
                  className="w-full px-4 py-4 border border-[#cfb99d] bg-[#fffaf1] outline-none focus:border-[#B56A3E] transition"
                  placeholder="Collector email"
                  value={collector.email}
                  onChange={(e) => setCollector((c) => ({ ...c, email: e.target.value }))}
                />
                <button
                  onClick={handleAcquire}
                  disabled={acquiring}
                  className="bg-[#1C1A16] hover:bg-black transition duration-300 text-[#F7F0E1] py-4 px-6 tracking-wide shadow-xl disabled:opacity-50"
                >
                  {acquiring ? "Submitting grouped settlement..." : "Acquire Artwork"}
                </button>
              </div>
              <p className="text-xs text-[#8B694D] mt-3 uppercase tracking-[0.18em]">
                Payment and ownership change either both succeed or both fail.
              </p>
            </div>

            {settlementInfo ? (
              <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-7">
                <h2 className="text-2xl font-serif mb-4">Latest Settlement</h2>
                <div className="space-y-2 text-sm text-[#6D5646]">
                  <div>Network: <span className="text-[#2B1D16]">{settlementInfo.network}</span></div>
                  <div>Amount: <span className="text-[#2B1D16]">{settlementInfo.amount} microAlgos</span></div>
                  <div>Receiver: <span className="font-mono text-xs text-[#2B1D16] break-all">{settlementInfo.receiver}</span></div>
                  <div>App call: <span className="font-mono text-xs text-[#2B1D16] break-all">{settlementInfo.app_call_tx_id}</span></div>
                  <div>Payment: <span className="font-mono text-xs text-[#2B1D16] break-all">{settlementInfo.payment_tx_id}</span></div>
                  {settlementInfo.explorer_url ? (
                    <a
                      href={settlementInfo.explorer_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[#B56A3E] hover:underline"
                    >
                      View settlement on Pera Explorer <ExternalLink size={12} />
                    </a>
                  ) : null}
                </div>
              </div>
            ) : null}

            <div className="bg-[#F7F0E1]/85 border border-[#d8c6aa] shadow-[0_10px_50px_rgba(0,0,0,0.08)] p-7">
              <h2 className="text-2xl font-serif mb-4">Provenance Timeline</h2>
              <div className="space-y-3">
                {provenance.length === 0 ? (
                  <div className="text-sm text-[#6D5646]">No events yet.</div>
                ) : (
                  provenance.map((ev) => (
                    <div key={ev.id} className="p-3 bg-[#fffaf1] border border-[#d8c6aa]">
                      <div className="flex items-center justify-between gap-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-[#8B694D]">
                          {ev.provenance_event_type || ev.event_type}
                        </div>
                        <div className="text-xs text-[#6D5646]">{ev.created_at}</div>
                      </div>
                      <div className="mt-2 text-sm text-[#2B1D16] break-words">{ev.event_type}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
