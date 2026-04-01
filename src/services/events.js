import { EventEmitter } from "node:events";

// Shared event bus for real-time updates across the panel
const bus = new EventEmitter();
bus.setMaxListeners(0);

export default bus;
