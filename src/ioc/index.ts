/**
 * IOC (Indicator of Compromise) Module
 *
 * Provides types and utilities for IOC management with priority-based enforcement.
 */

export {
  type IOCPriority,
  type PrioritizedIOC,
  type PartitionedIOCs,
  type PriorityAssignmentResult,
  MAX_DNR_RULES,
  DEFAULT_PRIORITY,
  partitionByPriority,
  assignPriority,
  getIOCPriority,
  isIOCExpired,
  filterExpiredIOCs,
  createPrioritizedIOC,
  demoteToAsync,
  promoteToSync,
  getPriorityStats,
} from './priority';
