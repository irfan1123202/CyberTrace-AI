import { useCallback, useState } from 'react';
import { runTrace, buildEvidenceHashChain, getStages } from '../services/traceService';

export function useTrace() {
  const [status, setStatus] = useState('idle'); // idle | running | done | error
  const [activeStage, setActiveStage] = useState(null);
  const [result, setResult] = useState(null);
  const [hash, setHash] = useState(null);

  const stages = getStages();

  const start = useCallback(async (caseItem) => {
    setStatus('running');
    setResult(null);
    setHash(null);
    try {
      const traceResult = await runTrace(caseItem.headerSample, (stageKey) =>
        setActiveStage(stageKey)
      );
      setResult(traceResult);
      const evidenceHash = await buildEvidenceHashChain(caseItem.id, traceResult);
      setHash(evidenceHash);
      setStatus('done');
    } catch (e) {
      setStatus('error');
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setActiveStage(null);
    setResult(null);
    setHash(null);
  }, []);

  return { status, activeStage, result, hash, stages, start, reset };
}
