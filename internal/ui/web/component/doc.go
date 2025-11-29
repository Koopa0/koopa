// Package component provides reusable templ UI components for the GenUI web interface.
//
// This package contains atomic components (Button, Input, Avatar, etc.) and
// composite components (MessageBubble, ChatInput, etc.) that are used to build
// the chat interface.
//
// Component Design Principles:
//   - All components use Props structs for configuration
//   - Components are self-contained with Tailwind CSS classes
//   - Accessibility (ARIA labels, focus states) is built-in
//   - Dark mode support via Tailwind's dark: variant
package component
