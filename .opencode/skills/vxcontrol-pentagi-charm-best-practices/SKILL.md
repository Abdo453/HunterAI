---
name: "vxcontrol-pentagi-charm-best-practices"
description: "> Proven patterns and anti-patterns for building high-performance TUI applications. **Problem**: Multiple renderer instances cause freezing and memory leaks **Solution**: Create once, reuse everywhere"
---

# Vxcontrol Pentagi Charm Best Practices

*Sourced from vxcontrol-pentagi*

# Charm.sh Best Practices & Performance Guide

> Proven patterns and anti-patterns for building high-performance TUI applications.

## 🚀 **Performance Best Practices**

### **Single Glamour Renderer (Critical)**
**Problem**: Multiple renderer instances cause freezing and memory leaks
**Solution**: Create once, reuse everywhere

```go
// ✅ CORRECT: Single renderer instance
type Styles struct {
    renderer *glamour.TermRenderer
}

func New() *Styles {
    renderer, _ := glamour.NewTermRenderer(
        glamour.WithAutoStyle(),
        glamour.WithWordWrap(80),
    )
    return &Styles{renderer: renderer}
}

func (s *Styles) GetRenderer() *glamour.TermRenderer {
    return s.renderer
}

// Usage: Always use shared renderer
rendered, _ := m.styles.GetRenderer().Render(content)

// ❌ WRONG: Creating new renderer each time
func renderContent(content string) string {
    renderer, _ := glamour.NewTermRenderer(...) // Memory leak + freeze risk!
    return renderer.Render(content)
}
```

### **Centralized Dimension Management**
**Problem**: Dimensions stored in models cause sync issues
**Solution**: Single source of truth in styles

```go
// ✅ CORRECT: Centralized dimensions
type Styles struct {
    width  int
    height int
}

func (s *Styles) SetSize(width, height int) {
    s.width = width
    s.height = height
    s.updateStyles() // Recalculate responsive styles
}

func (s *Styles) GetSize() (int, int) {
    return s.width, s.height
}

// Models use styles for dimensions
func (m *Model) updateViewport() {
    width, height := m.styles.GetSize()
    // ... safe dimension usage
}

// ❌ WRONG: Models managing dimensions
type Model struct {
    width, height int // Will get out of sync!
}
```

### **Efficient Viewport Usage**

#### **Permanent vs Temporary Viewports**
```go
// ✅ CORRECT: Permanent viewport for forms (preserves scroll state)
type FormModel struct {
    viewport viewport.Model // Permanent - keeps scroll position
}

func (m *FormModel) ensureFocusVisible() {
    // Scroll calculations use permanent viewport state
    if focusY < m.viewport.YOffset {
        m.viewport.YOffset = focusY
    }
}

// ✅ CORRECT: Temporary viewport for layout rendering
func (m *Model) renderHorizontalLayout(left, right string, width, height int) string {
    content := lipgloss.JoinHorizontal(lipgloss.Top, leftStyled, rightStyled)

    // Create viewport just for rendering
    vp := viewport.New(width, height-PaddingHeight)
    vp.SetContent(content)
    return vp.View()
}

// ❌ WRONG: Creating viewport in View() - loses scroll state
func (m *FormModel) View() string {
    vp := viewport.New(width, height) // State lost on re-render!
    return vp.View()
}
```

### **Content Loading Optimization**
```go
// ✅ CORRECT: Lazy loading with caching
type Model struct {
    contentCache map[string]string
    loadOnce     sync.Once
}

func (m *Model) loadContent() tea.Cmd {
    return func() tea.Msg {
        // Check cache first
        if cached, exists := m.contentCache[m.contentKey]; exists {
            return ContentLoadedMsg{cached}
        }

        // Load and cache
        content, err := m.loadFromSource()
        if err != nil {
            return ErrorMsg{err}
        }

        m.contentCache[m.contentKey] = content
        return ContentLoadedMsg{content}
    }
}

// ❌ WRONG: Loading on every Init()
func (m *Model) Init() tea.Cmd {
    return m.loadContent // Reloads every time!
}
```

## 🎯 **Architecture Best Practices**

### **Clean Separation of Concerns**
```go
// ✅ CORRECT: Clear responsibilities
// app.go - Global navigation, layout management, shared resources
type App struct {
    navigator    *Navigator      // Navigation state
    currentModel tea.Model       // Current screen
    styles       *Styles         // Shared styling
    window       *Window         // Dimension management
    controller   *Controller     // Business logic
}

// models/ - Screen-specific logic only
type ScreenModel struct {
    // Screen-specific state only
    content string
    ready   bool

    // Injected dependencies
    styles     *Styles
    window     *Window
    controller *Controller
}

// controller/ - Business logic, no UI concerns
type Controller struct {
    state *State
}

func (c *Controller) GetConfiguration() Config {
    // Pure business logic, no UI dependencies
}

// ❌ WRONG: Mixed responsibilities
type Model struct {
    // UI state
    viewport viewport.Model

    // Business logic (should be in controller)
    database *sql.DB
    apiClient *http.Client

    // Global state (should be in app)
    allScreens map[string]tea.Model
}
```

### **Resource Management**
```go
// ✅ CORRECT: Dependency injection
func NewApp() *App {
    // Create shared resources once
    styles := styles.New()
    window := window.New()
    controller := controller.New()

    return &App{
        styles:     styles,
        window:     window,
        controller: controller,
    }
}

func (a *App) createModelForScreen(screenID ScreenID) tea.Model {
    // Inject shared dependencies
    return NewScreenModel(a.styles, a.window, a.controller)
}

// ❌ WRONG: Resource duplication
func NewScreenModel() *ScreenModel {
    return &ScreenModel{
        styles:     styles.New(),     // Multiple instances!
        controller: controller.New(), // Multiple instances!
    }
}
```

## 🎯 **State Management Best Practices**

### **Complete State Reset Pattern**
```go
// ✅ CORRECT: Reset ALL state in Init()
func (m *Model) Init() tea.Cmd {
    // Reset UI state
    m.content = ""
    m.ready = false
    m.error = nil
    m.initialized = false

    // Reset component state
    m.viewport.GotoTop()
    m.viewport.SetContent("")

    // Reset form state
    m.focusedIndex = 0
    m.hasChanges = false
    for i := range m.fields {
        m.fields[i].Input.Blur()
    }

    // Reset navigation args
    m.selectedIndex = m.getSelectedIndexFromArgs()

    return m.loadContent
}

// ❌ WRONG: Partial state reset
func (m *Model) Init() tea.Cmd {
    m.content = "" // Only resetting some fields!
    return m.loadContent
}
```

### **Args-Based Construction**
```go
// ✅ CORRECT: Selection from constructor args
func NewModel(args []string) *Model {
    selectedIndex := 0
    if len(args) > 0 && args[0] != "" {
        for i, item := range items {
            if item.ID == args[0] {
                selectedIndex = i
                break
            }
        }
    }

    return &Model{
        selectedIndex: selectedIndex,
        args:          args,
    }
}

// No separate SetSelected methods needed
func (m *Model) Init() tea.Cmd {
    // Selection already set in constructor
    return m.loadData
}

// ❌ WRONG: Separate setter methods
func (m *Model) SetSelectedItem(itemID string) {
    // Adds complexity, sync issues
    for i, item := range m.items {
        if item.ID == itemID {
            m.selectedIndex = i
            break
        }
    }
}
```

## 🎯 **Navigation Best Practices**

### **Type-Safe Navigation**
```go
// ✅ CORRECT: Type-safe constants and helpers
type ScreenID string
const (
    WelcomeScreen ScreenID = "welcome"
    MenuScreen    ScreenID = "menu"
)

func CreateScreenID(screen string, args ...string) ScreenID {
    if len(args) == 0 {
        return ScreenID(screen)
    }
    return ScreenID(screen + "§" + strings.Join(args, "§"))
}

// Usage
return NavigationMsg{Target: CreateScreenID("form", "provider", "openai")}

// ❌ WRONG: String-based navigation
return NavigationMsg{Target: "form/provider/openai"} // Typo-prone!
```

### **GoBack Navigation Pattern**
```go
// ✅ CORRECT: Use GoBack to prevent loops
func (m *FormModel) saveAndReturn() (tea.Model, tea.Cmd) {
    if err := m.saveConfiguration(); err != nil {
        return m, nil // Stay on form if save fails
    }

    return m, func() tea.Msg {
        return NavigationMsg{GoBack: true} // Return to previous screen
    }
}

// ❌ WRONG: Direct navigation creates loops
func (m *FormModel) saveAndReturn() (tea.Model, tea.Cmd) {
    m.saveConfiguration()
    return m, func() tea.Msg {
        return NavigationMsg{Target: ProvidersScreen} // Creates navigation loop!
    }
}
```

## 🎯 **Form Best Practices**

### **Dynamic Width Management**
```go
// ✅ CORRECT: Calculate width dynamically
func (m *FormModel) updateFormContent() {
    inputWidth := m.getInputWidth()

    for i, field := range m.fields {
        // Apply width during rendering, not initialization
        field.Input.Width = inputWidth - 3
        field.Input.SetValue(field.Input.Value()) // Trigger width update
    }
}

func (m *FormModel) getInputWidth() int {
    viewportWidth, _ := m.getViewportSize()
    inputWidth := viewportWidth - 6 // Account for padding
    if m.isVerticalLayout() {
        inputWidth = viewportWidth - 4 // Less padding in vertical
    }
    return inputWidth
}

// ❌ WRONG: Fixed width at initialization
func (m *FormModel) createField() {
    input := textinput.New()
    input.Width = 50 // Breaks responsive design!
}
```

### **Environment Variable Integration**
```go
// ✅ CORRECT: Track initial state for cleanup
func (m *FormModel) buildForm() {
    m.initiallySetFields = make(map[string]bool)

    for _, fieldConfig := range m.fieldConfigs {
        envVar, _ := m.controller.GetVar(fieldConfig.EnvVarName)

        // Track if field was initially set
        m.initiallySetFields[fieldConfig.Key] = envVar.IsPresent()

        field := m.createFieldFromEnvVar(fieldConfig, envVar)
        m.fields = append(m.fields, field)
    }
}

func (m *FormModel) saveConfiguration() error {
    // First pass: Remove cleared fields
    for _, field := range m.fields {
        value := strings.TrimSpace(field.Input.Value())

        if value == "" && m.initiallySetFields[field.Key] {
            // Field was set but now empty - remove from environment
            m.controller.SetVar(field.EnvVarName, "")
        }
    }

    // Second pass: Save non-empty values
    for _, field := range m.fields {
        value := strings.TrimSpace(field.Input.Value())
        if value != "" {
            m.controller.SetVar(field.EnvVarName, value)
        }
    }

    return nil
}

// ❌ WRONG: No cleanup tracking
func (m *FormModel) saveConfiguration() error {
    for _, field := range m.fields {
        // Always sets value, even if it should be removed
        m.controller.SetVar(field.EnvVarName, field.Input.Value())
    }
}
```

## 🎯 **Layout Best Practices**

### **Responsive Breakpoints**
```go
// ✅ CORRECT: Consistent breakpoint logic
const (
    MinTerminalWidth = 80
    MinMenuWidth     = 38
    MaxMenuWidth     = 66
    MinInfoWidth     = 34
    PaddingWidth     = 8
)

func (m *Model) isVerticalLayout() bool {
    contentWidth := m.window.GetContentWidth()
    return contentWidth < (MinMenuWidth + MinInfoWidth + PaddingWidth)
}

func (m *Model) renderHorizontalLayout(leftPanel, rightPanel string, width, height int) string {
    leftWidth, rightWidth := MinMenuWidth, MinInfoWidth
    extraWidth := width - leftWidth - rightWidth - PaddingWidth

    if extraWidth > 0 {
        leftWidth = min(leftWidth+extraWidth/2, MaxMenuWidth) // Cap at max
        rightWidth = width - leftWidth - PaddingWidth/2
    }

    // ... render with calculated widths
}

// ❌ WRONG: Arbitrary breakpoints
func (m *Model) isVerticalLayout() bool {
    return m.width < 85 // Magic number!
}
```

### **Content Hiding Strategy**
```go
// ✅ CORRECT: Graceful content hiding
func (m *Model) renderVerticalLayout(leftPanel, rightPanel string, width, height int) string {
    leftStyled := verticalStyle.Render(leftPanel)
    rightStyled := verticalStyle.Render(rightPanel)

    // Show both panels if they fit
    if lipgloss.Height(leftStyled)+lipgloss.Height(rightStyled)+2 < height {
        return lipgloss.JoinVertical(lipgloss.Left, leftStyled, "", rightStyled)
    }

    // Hide right panel if insufficient space - show only essential content
    return leftStyled
}

// ❌ WRONG: Always showing all content
func (m *Model) renderVerticalLayout(leftPanel, rightPanel string, width, height int) string {
    // Forces both panels even if they don't fit
    return lipgloss.JoinVertical(lipgloss.Left, leftPanel, rightPanel)
}
```

## 🚀 **Performance Optimization**

### **Memory Management**
```go
// ✅ CORRECT: Efficient string building
func (m *Model) buildLargeContent() string {
    var builder strings.Builder
    builder.Grow(1024) // Pre-allocate capacity

    for _, section := range m.sections {
        builder.WriteString(section)
        builder.WriteString("\n")
    }

    return builder.String()
}

// ❌ WRONG: String concatenation in loop
func (m *Model) buildLargeContent() string {
    content := ""
    for _, section := range m.sections {
        content += section + "\n" // Creates new string each iteration!
    }
    return content
}
```

### **Viewport Content Updates**
```go
// ✅ CORRECT: Update content only when changed
func (m *Model) updateViewportContent() {
    newContent := m.buildContent()

    // Only update if content changed
    if newContent != m.lastContent {
        m.viewport.SetContent(newContent)
        m.lastContent = newContent
    }
}

// ❌ WRONG: Always updating content
func (m *Model) View() string {
    content := m.buildContent()
    m.viewport.SetContent(content) // Updates every render!
    return m.viewport.View()
}
```

## 🚀 **Error Handling Best Practices**

### **Graceful Degradation**
```go
// ✅ CORRECT: Multiple fallback levels
func (m *Model) View() string {
    width, height := m.styles.GetSize()
    if width <= 0 || height <= 0 {
        return "Loading..." // Dimension fallback
    }

    if m.error != nil {
        return m.styles.Error.Render("Error: " + m.error.Error()) // Error fallback
    }

    if !m.ready {
        return m.styles.Info.Render("Loading content...") // Loading fallback
    }

    return m.viewport.View() // Normal rendering
}

// ❌ WRONG: No fallbacks
func (m *Model) View() string {
    return m.viewport.View() // Crashes if viewport not initialized!
}
```

### **Safe Async Operations**
```go
// ✅ CORRECT: Safe async with error handling
func (m *Model) loadContent() tea.Cmd {
    return func() tea.Msg {
        defer func() {
            if r := recover(); r != nil {
                return ErrorMsg{fmt.Errorf("panic in loadContent: %v", r)}
            }
        }()

        content, err := m.loadFromSource()
        if err != nil {
            return ErrorMsg{err}
        }

        return ContentLoadedMsg{content}
    }
}

// ❌ WRONG: No error handling
func (m *Model) loadContent() tea.Cmd {
    return func() tea.Msg {
        content, _ := m.loadFromSource() // Ignores errors!
        return ContentLoadedMsg{content}
    }
}
```

## 🎯 **Key Anti-Patterns to Avoid**

### **❌ Don't Do These**
```go
// ❌ NEVER: Console output in TUI
fmt.Println("debug")
log.Println("debug")

// ❌ NEVER: Multiple glamour renderers
renderer1 := glamour.NewTermRenderer(...)
renderer2 := glamour.NewTermRenderer(...)

// ❌ NEVER: Dimensions in models
type Model struct {
    width, height int
}

// ❌ NEVER: Direct navigation creating loops
return NavigationMsg{Target: PreviousScreen}

// ❌ NEVER: Fixed input widths
input.Width = 50

// ❌ NEVER: Partial state reset
func (m *Model) Init() tea.Cmd {
    m.content = "" // Missing other state!
}

// ❌ NEVER: ClearScreen during navigation
return tea.Batch(cmd, tea.ClearScreen)

// ❌ NEVER: String-based navigation
return NavigationMsg{Target: "screen_name"}
```

### **✅ Always Do These**
```go
// ✅ ALWAYS: File-based logging
logger.Log("[Component] EVENT: %v", msg)

// ✅ ALWAYS: Single shared renderer
rendered := m.styles.GetRenderer().Render(content)

// ✅ ALWAYS: Centralized dimensions
width, height := m.styles.GetSize()

// ✅ ALWAYS: GoBack navigation
return NavigationMsg{GoBack: true}

// ✅ ALWAYS: Dynamic input sizing
input.Width = m.getInputWidth()

// ✅ ALWAYS: Complete state reset
func (m *Model) Init() tea.Cmd {
    m.resetAllState()
    return m.loadContent
}

// ✅ ALWAYS: Clean model initialization
return a, a.currentModel.Init()

// ✅ ALWAYS: Type-safe navigation
return NavigationMsg{Target: CreateScreenID("screen", "arg")}
```

This guide ensures:
- **Performance**: Efficient resource usage and rendering
- **Reliability**: Robust error handling and state management
- **Maintainability**: Clean architecture and consistent patterns
- **User Experience**: Responsive design and graceful degradation
