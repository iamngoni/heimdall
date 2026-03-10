//
//  heimdall
//  src/templates.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use minijinja::{Environment, path_loader};
use std::sync::Arc;

/// Holds the minijinja template environment.
pub struct TemplateEngine {
    env: Environment<'static>,
}

impl TemplateEngine {
    /// Initialize the template engine, loading templates from the given directory.
    pub fn new(template_dir: &str) -> Self {
        let mut env = Environment::new();
        env.set_loader(path_loader(template_dir));
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

/// Create a shared template engine instance.
pub fn init_templates(template_dir: &str) -> Arc<TemplateEngine> {
    Arc::new(TemplateEngine::new(template_dir))
}
