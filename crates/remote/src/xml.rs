//! The one XML walk both list parsers share: namespace prefixes are dropped
//! (`D:href`, `d:href` and `href` are one element), text is unescaped, and
//! each element is reported when it closes with its path and direct text.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::RemoteError;

/// The deepest element nesting a response may use.
const MAX_DEPTH: usize = 32;

/// Calls `on_close(path, text)` as each element closes; `path` ends with the
/// element's own local name and `text` is its exact direct text, untrimmed
/// (a continuation token may carry whitespace); parsers trim the fields
/// that tolerate it.
pub(crate) fn walk(
    xml: &str,
    mut on_close: impl FnMut(&[String], &str) -> Result<(), RemoteError>,
) -> Result<(), RemoteError> {
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|e| RemoteError::Protocol(format!("XML: {e}")))?;
        match event {
            Event::Start(start) => {
                if path.len() >= MAX_DEPTH {
                    return Err(RemoteError::Protocol("XML nested too deeply".into()));
                }
                path.push(start.local_name().as_ref().to_owned());
                texts.push(String::new());
            }
            Event::Empty(start) => {
                path.push(start.local_name().as_ref().to_owned());
                on_close(&path, "")?;
                path.pop();
            }
            Event::End(end) => {
                if path.last().map(String::as_str) != Some(end.local_name().as_ref()) {
                    return Err(RemoteError::Protocol("mismatched XML end tag".into()));
                }
                let text = texts.pop().unwrap_or_default();
                on_close(&path, &text)?;
                path.pop();
            }
            Event::Text(text) => {
                if let Some(buf) = texts.last_mut() {
                    buf.push_str(&text.xml10_content());
                }
            }
            Event::CData(data) => {
                if let Some(buf) = texts.last_mut() {
                    buf.push_str(&data);
                }
            }
            Event::GeneralRef(reference) => {
                let ch = match reference
                    .resolve_char_ref()
                    .map_err(|e| RemoteError::Protocol(format!("XML: {e}")))?
                {
                    Some(ch) => ch,
                    None => match &*reference {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        other => {
                            return Err(RemoteError::Protocol(format!(
                                "unknown XML entity &{other};"
                            )));
                        }
                    },
                };
                if let Some(buf) = texts.last_mut() {
                    buf.push(ch);
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    if !path.is_empty() {
        return Err(RemoteError::Protocol("truncated XML".into()));
    }
    Ok(())
}
