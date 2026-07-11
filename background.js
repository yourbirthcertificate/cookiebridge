chrome.action.onClicked.addListener(async () => {
  const appUrl = chrome.runtime.getURL("app.html");
  try {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ["TAB"],
      documentUrls: [appUrl],
    });
    const context = contexts.find((candidate) => Number.isInteger(candidate.tabId));
    if (context) {
      const tab = await chrome.tabs.update(context.tabId, { active: true });
      if (Number.isInteger(tab.windowId)) {
        await chrome.windows.update(tab.windowId, { focused: true });
      }
      return;
    }
  } catch {
    // Creating a fresh app tab remains safe if tab discovery is unavailable.
  }
  await chrome.tabs.create({ url: appUrl });
});
