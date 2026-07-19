//
//  heimdall
//  src/templates.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use minijinja::{Environment, path_loader};
use std::collections::HashMap;
use std::sync::Arc;

/// The single active theme. The multi-theme system (sentinel/oatmeal/editorial)
/// and the Appearance picker were retired in favor of one Basecoat theme.
pub const DEFAULT_THEME: &str = "heimdall";

/// Known theme identifiers. Only one theme ships now.
pub const KNOWN_THEMES: &[&str] = &["heimdall"];

/// Normalize any stored/legacy theme identifier to the single active theme.
/// Users whose `theme` column still holds an old value resolve to `heimdall`.
pub fn normalize_theme(theme: &str) -> &str {
    match theme {
        candidate if KNOWN_THEMES.contains(&candidate) => candidate,
        _ => DEFAULT_THEME,
    }
}

/// Register shared minijinja filters used across all themes/templates.
fn register_filters(env: &mut Environment<'static>) {
    // `short_dt`: render any stored timestamp compactly as "YYYY-MM-DD HH:MM".
    // Backend datetimes serialize as RFC3339 (e.g. 2026-07-16T19:38:18.666388+00:00);
    // rendered raw they overflow narrow columns. Also tolerates already-short and
    // missing/empty values. Drops seconds, microseconds, and the timezone suffix.
    env.add_filter("short_dt", |value: Option<String>| -> String {
        match value {
            Some(s) if !s.trim().is_empty() => {
                s.trim().replacen('T', " ", 1).chars().take(16).collect()
            }
            _ => "—".to_string(),
        }
    });
}

/// Holds the minijinja template environment for a single theme.
pub struct TemplateEngine {
    env: Environment<'static>,
}

impl TemplateEngine {
    /// Initialize the template engine, loading templates from the given directory.
    pub fn new(template_dir: &str) -> Self {
        let mut env = Environment::new();
        env.set_loader(path_loader(template_dir));
        register_filters(&mut env);
        Self { env }
    }

    /// Render a template by name with the given serializable context.
    pub fn render<S: serde::Serialize>(
        &self,
        template_name: &str,
        context: S,
    ) -> Result<String, minijinja::Error> {
        let tmpl = self.env.get_template(template_name)?;
        tmpl.render(context)
    }
}

/// Registry of all available themes, each backed by its own TemplateEngine.
///
/// Ghost-style: every theme is a self-contained directory of templates.
/// The registry discovers themes from `{base_dir}/themes/` at startup.
pub struct ThemeRegistry {
    themes: HashMap<String, Arc<TemplateEngine>>,
    default_theme: String,
}

impl ThemeRegistry {
    /// Scan `{base_dir}/themes/` for subdirectories. Each subdirectory name
    /// becomes a theme identifier with its own TemplateEngine.
    pub fn new(base_dir: &str) -> Self {
        let themes_dir = format!("{base_dir}/themes");
        let mut themes = HashMap::new();

        let entries = std::fs::read_dir(&themes_dir).unwrap_or_else(|e| {
            panic!("Failed to read themes directory '{themes_dir}': {e}");
        });

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
            if !is_dir {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path().to_string_lossy().to_string();

            log::info!("Loading theme '{name}' from {path}");
            themes.insert(name, Arc::new(TemplateEngine::new(&path)));
        }

        if !themes.contains_key(DEFAULT_THEME) {
            panic!(
                "Default theme '{DEFAULT_THEME}' not found in '{themes_dir}'. \
                 Available: {:?}",
                themes.keys().collect::<Vec<_>>()
            );
        }

        log::info!(
            "Theme registry initialized with {} theme(s): {:?}",
            themes.len(),
            themes.keys().collect::<Vec<_>>()
        );

        Self {
            themes,
            default_theme: DEFAULT_THEME.to_string(),
        }
    }

    /// Get the TemplateEngine for a theme, falling back to the default.
    pub fn get(&self, theme: &str) -> &TemplateEngine {
        self.themes
            .get(theme)
            .or_else(|| self.themes.get(&self.default_theme))
            .expect("default theme must exist")
    }

    /// List all available theme names.
    pub fn available_themes(&self) -> Vec<&str> {
        self.themes.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a theme name is valid.
    pub fn is_valid_theme(&self, theme: &str) -> bool {
        self.themes.contains_key(theme)
    }
}

/// Create a shared theme registry from the templates base directory.
pub fn init_themes(base_dir: &str) -> Arc<ThemeRegistry> {
    Arc::new(ThemeRegistry::new(base_dir))
}
