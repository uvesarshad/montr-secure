"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client.js";
import { qk } from "./keys.js";
import { useActor } from "../../components/role-context.js";

/* ---------------------------------- queries ---------------------------------- */

export function useScans() {
  return useQuery({ queryKey: qk.scans, queryFn: api.listScans });
}

export function useScan(scanId: string) {
  return useQuery({
    queryKey: qk.scan(scanId),
    queryFn: () => api.getScan(scanId),
    enabled: !!scanId,
  });
}

export function useProgress(scanId: string, poll = false) {
  return useQuery({
    queryKey: qk.progress(scanId),
    queryFn: () => api.getProgress(scanId),
    enabled: !!scanId,
    refetchInterval: poll ? 4000 : false,
  });
}

export function useAppMap(scanId: string) {
  return useQuery({
    queryKey: qk.appMap(scanId),
    queryFn: () => api.getAppMap(scanId),
    enabled: !!scanId,
  });
}

export function useEstimate(scanId: string) {
  return useQuery({
    queryKey: qk.estimate(scanId),
    queryFn: () => api.getEstimate(scanId),
    enabled: !!scanId,
  });
}

export function useReport(scanId: string) {
  return useQuery({
    queryKey: qk.report(scanId),
    queryFn: () => api.getReport(scanId),
    enabled: !!scanId,
  });
}

export function useFixes(scanId: string) {
  return useQuery({
    queryKey: qk.fixes(scanId),
    queryFn: () => api.getFixes(scanId),
    enabled: !!scanId,
  });
}

export function useScanPullRequests(scanId: string) {
  return useQuery({
    queryKey: qk.scanPullRequests(scanId),
    queryFn: () => api.getScanPullRequests(scanId),
    enabled: !!scanId,
  });
}

export function usePullRequests() {
  return useQuery({ queryKey: qk.pullRequests, queryFn: api.listPullRequests });
}

export function useAudit(scanId?: string) {
  return useQuery({ queryKey: qk.audit(scanId), queryFn: () => api.listAudit(scanId) });
}

/* --------------------------------- mutations --------------------------------- */

export function useApproveEstimate(scanId: string) {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.approveEstimate(scanId, actor),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.scan(scanId) });
      void qc.invalidateQueries({ queryKey: qk.scans });
      void qc.invalidateQueries({ queryKey: qk.progress(scanId) });
      void qc.invalidateQueries({ queryKey: qk.audit() });
      void qc.invalidateQueries({ queryKey: qk.audit(scanId) });
    },
  });
}

export function useApproveFixGate(scanId: string) {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.approveFixGate(scanId, actor),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.scan(scanId) });
      void qc.invalidateQueries({ queryKey: qk.report(scanId) });
      void qc.invalidateQueries({ queryKey: qk.audit() });
      void qc.invalidateQueries({ queryKey: qk.audit(scanId) });
    },
  });
}

export function useAuthorizeDast(scanId: string) {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (stagingUrl: string) => api.authorizeDast(scanId, actor, stagingUrl),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.scan(scanId) });
      void qc.invalidateQueries({ queryKey: qk.scans });
      void qc.invalidateQueries({ queryKey: qk.audit() });
      void qc.invalidateQueries({ queryKey: qk.audit(scanId) });
    },
  });
}

export function useKillSwitch(scanId: string) {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (reason: string) => api.activateKillSwitch(scanId, actor, reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.scan(scanId) });
      void qc.invalidateQueries({ queryKey: qk.scans });
      void qc.invalidateQueries({ queryKey: qk.progress(scanId) });
      void qc.invalidateQueries({ queryKey: qk.audit() });
      void qc.invalidateQueries({ queryKey: qk.audit(scanId) });
    },
  });
}

export function useMarkFalsePositive(scanId: string) {
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { findingId: string; reason: string }) =>
      api.markFalsePositive(vars.findingId, actor, vars.reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.report(scanId) });
      void qc.invalidateQueries({ queryKey: qk.audit() });
      void qc.invalidateQueries({ queryKey: qk.audit(scanId) });
    },
  });
}
