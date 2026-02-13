// =============================================================================
// TESSERA — Markup Engine Services
// (Tessera v3.1 §7, §8)
// =============================================================================

export {
  createMarkupSession,
  getSessionState,
  switchActiveContentSet,
  executeOperation,
  undoOperation,
  redoOperation,
  generateOverlapReport,
  applyPattern,
  propagateSelection,
} from './sessions';

export {
  submitForReview,
  getReviewPackage,
  recordReviewDecision,
  resolveEscalation,
} from './approval';

export {
  generateSuggestions,
  checkCodedContentRisk,
  resolveSuggestion,
  listSuggestions,
} from './suggestions';
