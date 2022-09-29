use serde::Serialize;
use std::fmt::Debug;
use std::{error, fmt};

#[derive(Debug, Serialize)]
/// An error designed to be readable and user friendly.
pub struct Whoops<T: Serialize + PartialEq + Debug> {
    #[serde(rename = "errType")]
    /// When serialized into json, this should be kebab-cased string indicating the type of error that has occurred.
    pub err_type: T,

    /// The context of where this error occurred.
    /// This is a more “user-friendly” version of a stack trace.
    /// This context string should consist of context clauses, beginning
    /// with words such as “Whilst”, “During” or “When” … etc and
    /// must finish with a period and a newline character.
    /// Notice that context clauses describe wider and wider
    /// contexts as the message grows. This is designed so that
    /// as the error bubbles up, new context clauses can be
    /// appended to the end of an existing context message.
    ///
    /// # Example
    /// ```text
    /// Whilst typing my essay.
    /// During the week.
    /// During the semester.
    /// ```
    ///
    ///
    pub context: String,

    /// The reason why the error occurred, an error message.
    pub reason: String,

    /// A suggestion as to what the user or programmer can do to mitigate this error.
    pub suggestion: String,
}

impl<T: Serialize + PartialEq + Debug> Whoops<T> {
    /// Appends to a Whoops' context.
    ///
    /// Useful when bubbling up a Whoops error and providing
    /// more context to where the error occured
    ///
    /// # Examples
    /// ```
    /// # use rust_pastureen_portal_lib::*;
    /// let mut err = Whoops {
    ///     err_type:"example-err".into(),
    ///     context:"Whilst some lower level error happened.".into(),
    ///     reason:"An demonstration error".into(),
    ///     suggestion:"Be a better developer".into()
    /// };
    ///
    /// err.wrap_context("During the documentation example.");
    ///
    /// assert_eq!(err.context,"Whilst some lower level error happened.\nDuring the documentation example.")
    /// ```
    ///
    ///
    pub fn wrap_context(&mut self, context: &str) {
        self.context = format!("{}\n{}", self.context, context)
    }
}

impl<T: Serialize + PartialEq + Debug> fmt::Display for Whoops<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "
--- ERROR ---
Error Type: {:?}
Context: {}
Why: {}
Suggestion: {}
-------------
",
            self.err_type, self.context, self.reason, self.suggestion
        )
    }
}

impl<T: Serialize + PartialEq + Debug + Into<String>> error::Error for Whoops<T> {}
