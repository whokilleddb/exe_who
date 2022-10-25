// Custom Error 
use std::fmt;

// Structure to refer application errors
pub struct AppError {
    pub description: String
}

// Print error message
impl fmt::Display for AppError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

// Print error message in a different format
impl fmt::Debug for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AppError (\n\tdescription: {}\n)", self.description)
    }
}