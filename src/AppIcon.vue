<script setup lang="ts">
const props = withDefaults(defineProps<{name:string;label?:string}>(),{label:undefined});
// One local outline set keeps navigation and actions consistent without external scripts/fonts.
const paths:Record<string,string> = {
  send:"m22 2-7 20-4-9-9-4L22 2Zm0 0L11 13",
  chat:"M3 3h18v14H8l-5 4V3Zm4 5h10M7 12h7",
  webhook:"M8 8a3 3 0 1 1 6 0m-9 8a3 3 0 1 0 6 0m4 0a3 3 0 1 0 6 0M11 8 8 16m3 0h7",
  activity:"M3 12h4l3-8 4 16 3-8h4",
  monitor:"M4 3h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm8 14v4m-4 0h8M6 10h3l2-4 3 7 2-3h2",
  alert:"M12 3 2 20h20L12 3Zm0 6v5m0 3h.01",
  health:"M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 0 0 0-7.8ZM3 12h5l2-4 4 8 2-4h5",
  history:"M3 11a9 9 0 1 1 2.6 7M3 4v7h7m2-4v5l3 2",
  server:"M4 3h16v7H4V3Zm0 11h16v7H4v-7Zm3-8h.01M7 17h.01M11 6h6m-6 11h6",
  incident:"M7 3h7l4 4v14H4V3h3Zm7 0v5h4m-7 4v3m0 3h.01",
  shield:"M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Zm0 5v5m0 3h.01",
  bell:"M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9Zm-8 12a2 2 0 0 0 4 0",
  external:"M14 3h7v7m0-7L10 14M10 3H3v18h18v-7",
  audit:"M9 4H5v17h14V4h-4m-6-2h6v4H9V2Zm-1 9 2 2 5-5m-7 9h8",
  users:"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m14-17a4 4 0 0 1 0 8m6 9v-2a4 4 0 0 0-3-3.9M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z",
  settings:"m9 3-.8 3-2.8.8-2.2-1.3-2 3.5 2.3 2.2v2.6L1.2 16l2 3.5 2.2-1.3 2.8.8.8 3h4l.8-3 2.8-.8 2.2 1.3 2-3.5-2.3-2.2v-2.6l2.3-2.2-2-3.5-2.2 1.3-2.8-.8L13 3H9Zm6 9a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z",
  logs:"M5 3h14v18H5V3Zm3 5h8m-8 4h8m-8 4h5",
  plus:"M12 5v14M5 12h14", x:"m6 6 12 12M18 6 6 18",
  refresh:"M20 7a9 9 0 0 0-15-2L3 7m0-5v5h5M4 17a9 9 0 0 0 15 2l2-2m0 5v-5h-5",
  play:"m8 4 13 8-13 8V4Z",
  edit:"m15 4 5 5M4 20l5-1L21 7l-5-5L4 14v6Z",
  trash:"M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7",
  check:"m4 12 5 5L20 6", closecase:"M9 3H5v18h14V3h-4M9 2h6v4H9V2Zm-1 12 3 3 5-6",
  copy:"M9 9h12v12H9V9ZM5 15H3V3h12v2",
  download:"M12 3v12m-5-5 5 5 5-5M3 16v5h18v-5",
  clock:"M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-5v5l3 2",
  left:"m14 5-7 7 7 7M7 12h14", right:"m10 5 7 7-7 7M3 12h14",
  chevron:"m9 5 7 7-7 7", lock:"M5 10h14v11H5V10Zm3 0V6a4 4 0 0 1 8 0v4m-4 5v2",
  search:"M16 10a6 6 0 1 1-12 0 6 6 0 0 1 12 0Zm-1.5 4.5L21 21",
  expand:"M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"
};
</script>
<template><svg class="app-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" :aria-hidden="label?undefined:true" :role="label?'img':undefined" :aria-label="label" focusable="false"><path :d="paths[props.name]||paths.activity" /></svg></template>
<style scoped>.app-icon{display:inline-block;vertical-align:middle;flex-shrink:0}</style>
