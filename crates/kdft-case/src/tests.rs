    use super::*;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mft_staging_rejects_empty_oversized_and_out_of_partition_streams() {
        assert!(validate_ntfs_mft_staging_size(0, 1024).is_err());
        assert!(validate_ntfs_mft_staging_size(1025, 1024).is_err());
        assert!(
            validate_ntfs_mft_staging_size(MAX_STAGED_MFT_BYTES + 1, MAX_STAGED_MFT_BYTES + 1)
                .is_err()
        );
        validate_ntfs_mft_staging_size(1024, 1024).unwrap();
        validate_ntfs_mft_staging_size(MAX_STAGED_MFT_BYTES, MAX_STAGED_MFT_BYTES).unwrap();
    }

    fn test_ntfs_dir_child(
        name: &str,
        record_number: u64,
        sequence_number: u16,
        namespace: &str,
        namespace_priority: u8,
    ) -> NtfsDirChild {
        NtfsDirChild {
            name: name.to_string(),
            is_directory: false,
            size_bytes: 0,
            allocated_size: 0,
            file_record_number: record_number,
            sequence_number,
            parent_record_number: 5,
            parent_sequence_number: 1,
            hard_link_count: Some(2),
            mft_record_logical_offset: None,
            sequence_validated: true,
            directory_entry_source: "test",
            file_attribute_flags: 0,
            namespace: namespace.to_string(),
            namespace_priority,
            creation_time_raw: 0,
            creation_time_utc: None,
            modification_time_raw: 0,
            modification_time_utc: None,
            access_time_raw: 0,
            access_time_utc: None,
            mft_record_modification_time_raw: 0,
            mft_record_modification_time_utc: None,
            standard_creation_time_raw: None,
            standard_creation_time_utc: None,
            standard_modification_time_raw: None,
            standard_modification_time_utc: None,
            standard_access_time_raw: None,
            standard_access_time_utc: None,
            standard_mft_record_modification_time_raw: None,
            standard_mft_record_modification_time_utc: None,
            file_data_logical_offset: None,
        }
    }

    #[test]
    fn ntfs_directory_dedup_preserves_distinct_hard_link_names() {
        let children = deduplicate_ntfs_directory_children(vec![
            test_ntfs_dir_child("alpha.txt", 42, 3, "Win32", 4),
            test_ntfs_dir_child("beta.txt", 42, 3, "Win32", 4),
            test_ntfs_dir_child("ALPHA~1.TXT", 42, 3, "Dos", 1),
            test_ntfs_dir_child("alpha.txt", 42, 3, "Dos", 1),
        ]);
        let names = children
            .iter()
            .map(|child| child.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["alpha.txt", "beta.txt"]);
    }

    #[test]
    fn ntfs_mft_summary_merge_keeps_si_and_matching_file_name_distinct() {
        let mut metadata = serde_json::json!({
            "source_entry_name": "hardlink-b.txt",
            "ntfs_path": "Users/Alice/hardlink-b.txt",
            "ntfs_parent_record_number": 200,
            "ntfs_parent_sequence_number": 7,
            "ntfs_file_record_number": 300,
            "ntfs_sequence_number": 9,
            "ntfs_data_stream_name": "",
        });
        let summary = serde_json::json!({
            "sequence_number": 9,
            "hard_link_count": 2,
            "fixup_valid": true,
            "used_record_bytes": 800,
            "record_size": 1024,
            "base_record_number": 0,
            "base_record_sequence": 0,
            "attribute_parse_error_count": 0,
            "attribute_parse_errors": [],
            "attribute_parse_errors_omitted": 0,
            "attribute_list_present": false,
            "attributes": [],
            "standard_information": {
                "created_utc": "2026-07-01T01:02:03Z",
                "modified_utc": "2026-07-02T01:02:03Z",
                "mft_modified_utc": "2026-07-03T01:02:03Z",
                "accessed_utc": "2026-07-04T01:02:03Z",
                "flags": 32,
                "owner_id": 1,
                "security_id": 2,
                "quota": 0,
                "usn": 123,
            },
            "file_names": [
                {
                    "name": "hardlink-a.txt",
                    "namespace": "Win32",
                    "parent_record": 100,
                    "parent_sequence": 4,
                    "logical_size": 10,
                    "physical_size": 4096,
                    "created_utc": "2026-06-01T00:00:00Z",
                    "modified_utc": "2026-06-02T00:00:00Z",
                    "mft_modified_utc": "2026-06-03T00:00:00Z",
                    "accessed_utc": "2026-06-04T00:00:00Z",
                    "flags": 1,
                },
                {
                    "name": "hardlink-b.txt",
                    "namespace": "Win32",
                    "parent_record": 200,
                    "parent_sequence": 7,
                    "logical_size": 11,
                    "physical_size": 8192,
                    "created_utc": "2026-06-11T00:00:00Z",
                    "modified_utc": "2026-06-12T00:00:00Z",
                    "mft_modified_utc": "2026-06-13T00:00:00Z",
                    "accessed_utc": "2026-06-14T00:00:00Z",
                    "flags": 32,
                }
            ],
            "data_streams": [{
                "name": "",
                "resident": false,
                "size": 11,
                "allocated_size": 8192,
                "valid_data_size": 11,
                "attribute_flags": 16385,
                "attribute_flags_debug": "IS_COMPRESSED | ENCRYPTED",
            }],
        });

        merge_mft_summary_into_ntfs_metadata(&mut metadata, &summary);

        assert_eq!(
            metadata["ntfs_standard_creation_time_utc"].as_str(),
            Some("2026-07-01T01:02:03Z")
        );
        assert_eq!(
            metadata["ntfs_file_name_creation_time_utc"].as_str(),
            Some("2026-06-11T00:00:00Z")
        );
        assert_eq!(
            metadata["ntfs_creation_time_utc"].as_str(),
            Some("2026-06-11T00:00:00Z")
        );
        assert_eq!(metadata["ntfs_parent_record_number"].as_u64(), Some(200));
        assert_eq!(metadata["ntfs_data_size"].as_u64(), Some(11));
        assert_eq!(metadata["ntfs_allocated_size"].as_u64(), Some(8192));
        assert_eq!(
            metadata["ntfs_data_stream_compressed"].as_bool(),
            Some(true)
        );
        assert_eq!(metadata["ntfs_data_stream_encrypted"].as_bool(), Some(true));
        assert_eq!(metadata["ntfs_data_stream_sparse"].as_bool(), Some(false));
        assert_eq!(
            metadata["ntfs_stream_read_support"].as_str(),
            Some("metadata only; EFS-encrypted NTFS content requires decryption keys")
        );
    }

    #[test]
    fn ntfs_native_attribute_summary_merge_exposes_flattened_inventory() {
        let mut metadata = serde_json::json!({});
        let summary = serde_json::json!({
            "parser": "ntfs crate 0.4.0 flattened attribute iterator",
            "attribute_count": 2,
            "attributes": [
                {"type": "StandardInformation", "instance": 0},
                {"type": "Data", "name": "secret_note", "instance": 4}
            ],
            "attribute_error_count": 0,
            "attribute_errors": [],
            "attribute_errors_omitted": 0,
            "truncated": false,
            "complete": true,
            "attribute_list_resolution": "flattened iterator follows connected ATTRIBUTE_LIST entries",
        });
        merge_native_ntfs_attribute_summary(&mut metadata, &summary);
        assert_eq!(metadata["ntfs_native_attribute_count"].as_u64(), Some(2));
        assert_eq!(
            metadata["ntfs_native_attributes"][1]["name"].as_str(),
            Some("secret_note")
        );
        assert_eq!(
            metadata["ntfs_native_attribute_inventory_complete"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn ntfs_mft_path_normalization_preserves_windows_hierarchy() {
        assert_eq!(
            normalized_mft_ntfs_path(Path::new(r"$Root\Users\Alice\Downloads\General.zip")),
            Some("Users/Alice/Downloads/General.zip".to_string())
        );
        assert_eq!(normalized_mft_ntfs_path(Path::new("$Root")), None);
        assert_eq!(
            ntfs_internal_logical_path(
                "/Image Analysis/Volumes/003-Basic_data_partition",
                "Users/Alice/Downloads/General.zip"
            ),
            "/Image Analysis/Volumes/003-Basic_data_partition/Users/Alice/Downloads/General.zip"
        );
    }

    fn write_test_docx(path: &Path, body_text: &str) -> Result<()> {
        let document_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{body_text}</w:t></w:r></w:p></w:body>
</w:document>"#
        );
        write_test_docx_package(path, &document_xml, 0)
    }

    fn write_test_docx_package(
        path: &Path,
        document_xml: &str,
        unsupported_text_parts: usize,
    ) -> Result<()> {
        let file = fs::File::create(path)?;
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("[Content_Types].xml", options)?;
        writer.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#,
        )?;
        writer.start_file("word/document.xml", options)?;
        writer.write_all(document_xml.as_bytes())?;
        for index in 0..unsupported_text_parts {
            writer.start_file(format!("word/afchunk{index:04}.html"), options)?;
            writer.write_all(format!("<p>unsupported text {index}</p>").as_bytes())?;
        }
        writer.finish()?;
        Ok(())
    }

    fn write_test_zip(path: &Path) -> Result<()> {
        let file = fs::File::create(path)?;
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in [
            (
                "Finance/Allocation_Tracker_Q3.csv",
                "Department,Amount\nResearch,750000\n",
            ),
            (
                "Finance/payments_2026.csv",
                "Vendor,Amount\nContoso,250000\n",
            ),
            (
                "Finance/wire_transfer_pending.txt",
                "Wire transfer pending examiner review.",
            ),
            (
                "HR/Payroll_Q3_CONFIDENTIAL.txt",
                "Payroll material is confidential.",
            ),
            (
                "Projects/Project_ORION_notes.txt",
                "Project ORION controlled notes.",
            ),
        ] {
            writer.start_file(name, options)?;
            writer.write_all(content.as_bytes())?;
        }
        writer.finish()?;
        Ok(())
    }

    #[test]
    fn document_and_archive_passes_index_complete_searchable_content_without_renaming_sources(
    ) -> Result<()> {
        let case_path = unique_case_path("document-archive-parsing");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("document-archive-source");
        let docx_path = evidence_dir.join("Validation Narrative.docx");
        let zip_path = evidence_dir.join("General.zip");
        let distinctive_tail = "DISTINCTIVE-DOCX-TAIL-MARKER-742";
        write_test_docx(
            &docx_path,
            &format!(
                "{} {distinctive_tail}",
                "A".repeat(CONTENT_INDEX_BYTES + 512)
            ),
        )?;
        write_test_zip(&zip_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let before = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let source_doc = before
            .iter()
            .find(|entry| entry.name == "Validation Narrative.docx")
            .context("DOCX source was not indexed")?;
        let source_doc_identity = (
            source_doc.id,
            source_doc.name.clone(),
            source_doc.logical_path.clone(),
        );
        let source_zip = before
            .iter()
            .find(|entry| entry.name == "General.zip")
            .context("ZIP source was not indexed")?;
        let source_zip_identity = (
            source_zip.id,
            source_zip.name.clone(),
            source_zip.logical_path.clone(),
        );

        let archives = parse_archive_artifacts(&case_path, evidence_id)?;
        assert_eq!(archives.status, "completed");
        assert_eq!(archives.archives_found, 1);
        assert_eq!(archives.archives_parsed, 1);
        assert_eq!(archives.members_indexed, 5);
        assert_eq!(archives.parse_error_count, 0);

        let documents = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(documents.status, "completed");
        assert_eq!(documents.documents_found, 1);
        assert_eq!(documents.documents_parsed, 1);
        assert!(documents.segments_indexed >= 1);
        assert_eq!(documents.parse_error_count, 0);

        let after = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let after_doc = after
            .iter()
            .find(|entry| entry.id == source_doc_identity.0)
            .context("DOCX source disappeared")?;
        assert_eq!(
            (
                after_doc.id,
                after_doc.name.clone(),
                after_doc.logical_path.clone()
            ),
            source_doc_identity
        );
        let after_zip = after
            .iter()
            .find(|entry| entry.id == source_zip_identity.0)
            .context("ZIP source disappeared")?;
        assert_eq!(
            (
                after_zip.id,
                after_zip.name.clone(),
                after_zip.logical_path.clone()
            ),
            source_zip_identity
        );
        let member = after
            .iter()
            .find(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("archive_member")
                    && entry.metadata_json["archive_member_name_exact"].as_str()
                        == Some("Finance/wire_transfer_pending.txt")
            })
            .context("exact archive member was not normalized")?;
        assert_eq!(member.name, "Finance/wire_transfer_pending.txt");
        assert_eq!(
            member.metadata_json["archive_derived_from_entry_id"].as_i64(),
            Some(source_zip_identity.0)
        );

        let doc_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: distinctive_tail.to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 50,
                max_file_bytes: CONTENT_INDEX_BYTES as u64,
                category: None,
                file_types: None,
            },
        )?;
        assert!(doc_hits.iter().any(|hit| {
            hit.entry_id == source_doc_identity.0
                && hit.match_kind == "parsed_content"
                && hit.selection_offset.is_none()
        }));
        let archive_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "wire transfer pending examiner".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 50,
                max_file_bytes: CONTENT_INDEX_BYTES as u64,
                category: None,
                file_types: None,
            },
        )?;
        assert!(archive_hits.iter().any(|hit| {
            hit.entry_id == member.id
                && hit.match_kind == "parsed_content"
                && hit.source_path_exact.as_deref() == Some("Finance/wire_transfer_pending.txt")
        }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn zip_extension_without_zip_signature_is_a_disclosed_skip_not_truncation() -> Result<()> {
        let case_path = unique_case_path("zip-signature-mismatch");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("zip-signature-mismatch-source");
        fs::write(
            evidence_dir.join("General.zip"),
            b"Write-Host 'deleted clusters were reused; this is not a ZIP archive'",
        )?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;

        let archives = parse_archive_artifacts(&case_path, evidence_id)?;
        assert_eq!(archives.status, "completed");
        assert_eq!(archives.archives_found, 1);
        assert_eq!(archives.archives_parsed, 0);
        assert_eq!(archives.signature_mismatch_count, 1);
        assert_eq!(archives.parse_error_count, 0);
        assert!(!archives.truncated);
        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.name == "General.zip")
            .context("signature-mismatch source was not indexed")?;
        assert_eq!(
            entry.metadata_json["archive_parser"]["status"].as_str(),
            Some("skipped_signature_mismatch")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn document_parse_keyset_pages_every_snapshot_candidate_without_renaming() -> Result<()> {
        let case_path = unique_case_path("document-keyset-pages");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("document-keyset-source");
        let document_count = DOCUMENT_CANDIDATE_PAGE_SIZE + 3;
        for index in 0..document_count {
            write_test_docx(
                &evidence_dir.join(format!("Evidence Document {index:03}.docx")),
                &format!("bounded-page-marker-{index:03}"),
            )?;
        }

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let mut identities_before = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".docx"))
            .map(|entry| (entry.id, entry.name, entry.logical_path))
            .collect::<Vec<_>>();
        identities_before.sort_by_key(|identity| identity.0);
        assert_eq!(identities_before.len(), document_count);

        let parsed = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(parsed.status, "completed");
        assert_eq!(parsed.documents_found, document_count);
        assert_eq!(parsed.documents_parsed, document_count);
        assert_eq!(parsed.parse_error_count, 0);

        let conn = open_existing_case(&case_path)?;
        let sources_with_segments: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT entry_id)
             FROM filesystem_entry_text_segments
             WHERE parser_name = ?1",
            params![OOXML_PARSER_NAME],
            |row| row.get(0),
        )?;
        assert_eq!(sources_with_segments as usize, document_count);
        drop(conn);

        let mut identities_after = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".docx"))
            .map(|entry| (entry.id, entry.name, entry.logical_path))
            .collect::<Vec<_>>();
        identities_after.sort_by_key(|identity| identity.0);
        assert_eq!(identities_after, identities_before);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn document_parse_streams_many_segments_and_retains_tail() -> Result<()> {
        let case_path = unique_case_path("document-many-segments");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("document-many-segments-source");
        let source_path = evidence_dir.join("Long Narrative.docx");
        let tail = "STREAMED-DOCX-TAIL-9f02";
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut state = 0x5a17_2d91_u32;
        let mut body = String::with_capacity(ooxml::DEFAULT_MAX_SEGMENT_BYTES * 2 + 512);
        for _ in 0..(ooxml::DEFAULT_MAX_SEGMENT_BYTES * 2 + 257) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            body.push(alphabet[(state as usize) % alphabet.len()] as char);
        }
        body.push_str(tail);
        write_test_docx(&source_path, &body)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let source_entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.name == "Long Narrative.docx")
            .context("long DOCX source was not indexed")?;
        let parsed = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(parsed.status, "completed");
        assert!(parsed.segments_indexed >= 3);

        let conn = open_existing_case(&case_path)?;
        let segment_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM filesystem_entry_text_segments
             WHERE entry_id = ?1 AND parser_name = ?2",
            params![source_entry.id, OOXML_PARSER_NAME],
            |row| row.get(0),
        )?;
        assert_eq!(segment_count as usize, parsed.segments_indexed);
        let last_segment: Vec<u8> = conn.query_row(
            "SELECT content FROM filesystem_entry_text_segments
             WHERE entry_id = ?1 AND parser_name = ?2
             ORDER BY segment_index DESC LIMIT 1",
            params![source_entry.id, OOXML_PARSER_NAME],
            |row| row.get(0),
        )?;
        assert!(String::from_utf8(last_segment)?.contains(tail));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn document_parse_failure_rolls_back_partial_replacement_segments() -> Result<()> {
        let case_path = unique_case_path("document-stream-rollback");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("document-stream-rollback-source");
        let source_path = evidence_dir.join("Rollback Evidence.docx");
        write_test_docx(&source_path, "STABLE-PRIOR-DOCX-CONTENT")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let source_entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.name == "Rollback Evidence.docx")
            .context("rollback DOCX source was not indexed")?;
        let first = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(first.status, "completed");

        let prior_segments = {
            let conn = open_existing_case(&case_path)?;
            let mut stmt = conn.prepare(
                "SELECT segment_index, part_name, content
                 FROM filesystem_entry_text_segments
                 WHERE entry_id = ?1 AND parser_name = ?2
                 ORDER BY segment_index",
            )?;
            let rows = stmt.query_map(params![source_entry.id, OOXML_PARSER_NAME], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert!(!prior_segments.is_empty());

        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut state = 0x31c4_8a7d_u32;
        let mut replacement = String::with_capacity(ooxml::DEFAULT_MAX_SEGMENT_BYTES + 2_048);
        for _ in 0..(ooxml::DEFAULT_MAX_SEGMENT_BYTES + 2_048) {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            replacement.push(alphabet[(state as usize) % alphabet.len()] as char);
        }
        // The parser has already emitted one full segment when it reaches this
        // deliberate unexpected EOF, so the test exercises transaction rollback
        // after a replacement insert rather than an error before streaming.
        let malformed_document = format!(
            r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{replacement}</w:t></w:r></w:p>"#
        );
        write_test_docx_package(&source_path, &malformed_document, 0)?;
        let second = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(second.status, "truncated");
        assert_eq!(second.documents_parsed, 0);
        assert_eq!(second.parse_error_count, 1);

        let conn = open_existing_case(&case_path)?;
        let mut stmt = conn.prepare(
            "SELECT segment_index, part_name, content
             FROM filesystem_entry_text_segments
             WHERE entry_id = ?1 AND parser_name = ?2
             ORDER BY segment_index",
        )?;
        let rows = stmt.query_map(params![source_entry.id, OOXML_PARSER_NAME], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let retained_segments = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(retained_segments, prior_segments);
        let metadata_json: String = conn.query_row(
            "SELECT metadata_json FROM filesystem_entries WHERE id = ?1",
            params![source_entry.id],
            |row| row.get(0),
        )?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
        let parser = &metadata["document_parser"];
        assert_eq!(parser["status"], "error");
        assert_eq!(parser["replacement_committed"], false);
        assert_eq!(parser["replacement_rolled_back"], true);
        assert_eq!(parser["previous_segments_preserved"], true);
        assert_eq!(
            parser["previous_segments_retained"].as_i64(),
            Some(prior_segments.len() as i64)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn document_parse_caps_unsupported_disclosures_but_keeps_exact_counts() -> Result<()> {
        let case_path = unique_case_path("document-unsupported-bound");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("document-unsupported-bound-source");
        let source_path = evidence_dir.join("Unsupported Parts.docx");
        let document_xml = r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Body</w:t></w:r></w:p></w:body></w:document>"#;
        let unsupported_total = DOCUMENT_UNSUPPORTED_PART_DISPLAY_LIMIT + 7;
        write_test_docx_package(&source_path, document_xml, unsupported_total)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let source_entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.name == "Unsupported Parts.docx")
            .context("unsupported-parts DOCX source was not indexed")?;
        let parsed = parse_document_artifacts(&case_path, evidence_id)?;
        assert_eq!(parsed.status, "truncated");
        assert_eq!(parsed.documents_parsed, 1);
        assert_eq!(parsed.partial_documents, 1);
        assert_eq!(parsed.parse_error_count, 0);

        let conn = open_existing_case(&case_path)?;
        let metadata_json: String = conn.query_row(
            "SELECT metadata_json FROM filesystem_entries WHERE id = ?1",
            params![source_entry.id],
            |row| row.get(0),
        )?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
        let parser = &metadata["document_parser"];
        assert_eq!(parser["status"], "partial");
        assert_eq!(
            parser["unsupported_parts"].as_array().map(Vec::len),
            Some(DOCUMENT_UNSUPPORTED_PART_DISPLAY_LIMIT)
        );
        assert_eq!(
            parser["unsupported_parts_total"].as_u64(),
            Some(unsupported_total as u64)
        );
        assert_eq!(parser["unsupported_parts_omitted"].as_u64(), Some(7));
        assert_eq!(
            parser["unsupported_may_contain_text_count"].as_u64(),
            Some(unsupported_total as u64)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn indexed_browser_staging_exports_supported_files_and_sidecars_without_profile_tree_caps(
    ) -> Result<()> {
        let case_path = unique_case_path("browser-targeted-staging");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("browser-targeted-source");
        let profile = evidence_dir.join("User Data").join("Default");
        fs::create_dir_all(profile.join("Network"))?;
        fs::create_dir_all(profile.join("Cache"))?;
        fs::write(profile.join("History"), b"history-main")?;
        fs::write(profile.join("History-wal"), b"history-wal")?;
        fs::write(profile.join("Network").join("Cookies"), b"cookies-main")?;
        fs::write(profile.join("Network").join("Cookies-shm"), b"cookies-shm")?;
        fs::write(profile.join("Cache").join("f_000001"), b"unrelated-cache")?;
        fs::create_dir_all(evidence_dir.join("Network"))?;
        fs::write(evidence_dir.join("History"), b"root-history-main")?;
        fs::write(
            evidence_dir.join("History-journal"),
            b"root-history-journal",
        )?;
        fs::write(
            evidence_dir.join("Network").join("Cookies"),
            b"root-cookies-main",
        )?;
        // This matches the broad SQL prefilter but is not a parser sidecar.
        fs::write(evidence_dir.join("History-old"), b"unrelated-backup")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let output = unique_temp_dir("browser-targeted-output");
        let exported = export_indexed_browser_profile(
            &case_path,
            evidence_id,
            "User Data/Default",
            None,
            &output,
        )?;
        assert_eq!(exported, 4);
        assert_eq!(fs::read(output.join("History"))?, b"history-main");
        assert_eq!(fs::read(output.join("History-wal"))?, b"history-wal");
        assert_eq!(
            fs::read(output.join("Network").join("Cookies"))?,
            b"cookies-main"
        );
        assert_eq!(
            fs::read(output.join("Network").join("Cookies-shm"))?,
            b"cookies-shm"
        );
        assert!(!output.join("Cache").exists());

        // A browser database can live directly at the evidence root (for
        // example a manually extracted History file).  An empty profile path
        // denotes that root and must export the same supported source files.
        let root_profile_output = unique_temp_dir("browser-targeted-root-output");
        let root_exported = export_indexed_browser_profile(
            &case_path,
            evidence_id,
            "",
            None,
            &root_profile_output,
        )?;
        assert_eq!(root_exported, 3);
        assert_eq!(
            fs::read(root_profile_output.join("History"))?,
            b"root-history-main"
        );
        assert_eq!(
            fs::read(root_profile_output.join("History-journal"))?,
            b"root-history-journal"
        );
        assert_eq!(
            fs::read(root_profile_output.join("Network").join("Cookies"))?,
            b"root-cookies-main"
        );
        assert!(!root_profile_output.join("User Data").exists());
        assert!(!root_profile_output.join("History-old").exists());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(output);
        let _ = fs::remove_dir_all(root_profile_output);
        Ok(())
    }

    #[test]
    fn test_sanitize_logical_segment_preserves_dollar_sign() {
        assert_eq!(sanitize_logical_segment("$MFT"), "$MFT");
        assert_eq!(sanitize_logical_segment("$LogFile"), "$LogFile");
        assert_eq!(sanitize_logical_segment("test.txt"), "test.txt");
        assert_eq!(sanitize_logical_segment("some/path"), "some_path");
    }

    #[test]
    fn create_case_seeds_global_options_and_installed_resources() -> Result<()> {
        let case_path = unique_case_path("resources");
        create_test_case(&case_path)?;

        let options = global_options(&case_path)?;
        assert_eq!(options.id, 1);
        assert!(options.config_root.is_none());
        assert!(options.evidence_library_root.is_none());
        assert!(options.default_storage_root.is_none());

        let resources = list_installed_resources(&case_path)?;
        let keys = resources
            .iter()
            .map(|resource| resource.resource_key.as_str())
            .collect::<HashSet<_>>();
        assert!(keys.contains("file_signatures"));
        assert!(keys.contains("file_types"));
        assert!(keys.contains("filters"));
        assert!(keys.contains("keywords"));
        assert!(keys.contains("profiles"));
        assert!(keys.contains("text_styles"));
        assert!(keys.contains("case_report_template"));
        assert!(resources.iter().all(|resource| resource.enabled));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn create_case_never_replaces_an_existing_file() -> Result<()> {
        let case_path = unique_case_path("existing-case-preserved");
        let original = b"not a case database; preserve these bytes";
        fs::write(&case_path, original)?;

        let error = create_case(
            &case_path,
            CreateCaseOptions {
                name: "Must Not Replace".to_string(),
                examiner_name: None,
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
        .expect_err("creating a case over an existing file must fail");

        assert!(!format!("{error:#}").is_empty());
        assert_eq!(fs::read(&case_path)?, original);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn opening_an_unrelated_sqlite_database_never_migrates_or_modifies_it() -> Result<()> {
        let path = unique_case_path("unrelated-sqlite-preserved");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(
                "CREATE TABLE personal_notes(id INTEGER PRIMARY KEY, body TEXT);
                 INSERT INTO personal_notes(body) VALUES ('preserve me');",
            )?;
        }
        let before = fs::read(&path)?;

        let error = open_existing_case(&path).expect_err("an unrelated database must be rejected");
        assert!(format!("{error:#}").contains("not a complete KDFT case"));
        assert_eq!(fs::read(&path)?, before);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert!(!sqlite_table_exists(&conn, "cases")?);
        drop(conn);

        cleanup_case_path(&path);
        Ok(())
    }

    #[test]
    fn legacy_case_without_application_id_is_recognized_and_marked() -> Result<()> {
        let path = unique_case_path("legacy-application-id");
        create_test_case(&path)?;
        {
            let conn = Connection::open(&path)?;
            conn.pragma_update(None, "application_id", 0_i64)?;
        }

        assert_eq!(case_info(&path)?.id, 1);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let application_id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        assert_eq!(application_id, KDFT_APPLICATION_ID);
        drop(conn);

        cleanup_case_path(&path);
        Ok(())
    }

    #[test]
    fn case_database_rejects_second_case_row() -> Result<()> {
        let case_path = unique_case_path("single-case");
        create_test_case(&case_path)?;
        let conn = open_existing_case(&case_path)?;

        let err = conn
            .execute("INSERT INTO cases(id, name) VALUES (2, 'Second Case')", [])
            .expect_err("case database should reject a second case row")
            .to_string();
        assert!(err.contains("CHECK constraint failed"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn global_options_round_trip() -> Result<()> {
        let case_path = unique_case_path("options");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("options-root");
        let config_root = root.join("config");
        let evidence_library_root = root.join("evidence-library");
        let default_storage_root = root.join("storage");

        let updated = update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Set(config_root.clone())),
                evidence_library_root: Some(GlobalOptionPathUpdate::Set(
                    evidence_library_root.clone(),
                )),
                default_storage_root: Some(GlobalOptionPathUpdate::Set(
                    default_storage_root.clone(),
                )),
            },
        )?;
        let expected_config_root = path_str(&config_root);
        let expected_evidence_library_root = path_str(&evidence_library_root);
        let expected_default_storage_root = path_str(&default_storage_root);
        assert_eq!(
            updated.config_root.as_deref(),
            Some(expected_config_root.as_str())
        );
        assert_eq!(
            updated.evidence_library_root.as_deref(),
            Some(expected_evidence_library_root.as_str())
        );
        assert_eq!(
            updated.default_storage_root.as_deref(),
            Some(expected_default_storage_root.as_str())
        );

        let reread = global_options(&case_path)?;
        assert_eq!(reread.config_root, updated.config_root);
        assert_eq!(reread.evidence_library_root, updated.evidence_library_root);
        assert_eq!(reread.default_storage_root, updated.default_storage_root);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn global_options_clear_and_noop_do_not_create_spurious_audit() -> Result<()> {
        let case_path = unique_case_path("options-clear");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("options-clear-root");
        let config_root = root.join("config");

        update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Set(config_root)),
                evidence_library_root: None,
                default_storage_root: None,
            },
        )?;
        let after_set_count = audit_event_count(&case_path)?;

        let cleared = update_global_options(
            &case_path,
            UpdateGlobalOptions {
                config_root: Some(GlobalOptionPathUpdate::Clear),
                evidence_library_root: None,
                default_storage_root: None,
            },
        )?;
        assert!(cleared.config_root.is_none());
        assert_eq!(audit_event_count(&case_path)?, after_set_count + 1);

        let noop = update_global_options(&case_path, UpdateGlobalOptions::default())?;
        assert!(noop.config_root.is_none());
        assert_eq!(audit_event_count(&case_path)?, after_set_count + 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn audit_events_record_examiner_actor() -> Result<()> {
        let case_path = unique_case_path("audit-actor");
        create_test_case(&case_path)?;

        let actors = audit_event_actors(&case_path)?;
        assert!(!actors.is_empty());
        assert!(actors.iter().all(|actor| actor == "Test Examiner"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn evidence_attach_records_source_without_jobs_or_filesystem_entries() -> Result<()> {
        let case_path = unique_case_path("no-index");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("evidence-source");
        fs::write(evidence_dir.join("sample.txt"), b"small sample")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: Some("unit test".to_string()),
            },
        )?;
        assert_eq!(evidence_id, 1);
        assert_eq!(filesystem_entry_count(&case_path)?, 0);
        assert_eq!(evidence_job_count(&case_path)?, 0);

        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "folder");
        assert!(evidence[0].read_file_system_requested);
        assert_eq!(evidence[0].indexed_at, None);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn browser_database_attach_signals_import_without_plain_evidence_row() -> Result<()> {
        let case_path = unique_case_path("detected-browser-attach");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("detected-browser-profile");
        let history_path = profile_dir.join("History");
        create_test_chromium_history(&history_path)?;

        assert_eq!(
            detect_browser_database(&history_path)?,
            Some(BrowserFamily::Chromium)
        );
        let error = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: history_path,
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )
        .expect_err("a browser database should be routed to the history importer");
        let detected = error
            .downcast_ref::<BrowserDatabaseDetected>()
            .expect("attach should return the typed browser-database signal");
        assert_eq!(detected.family, BrowserFamily::Chromium);
        assert!(list_evidence(&case_path)?.is_empty());
        assert_eq!(filesystem_entry_count(&case_path)?, 0);

        let imported = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 2);
        assert!(imported.entries_indexed >= imported.visits_indexed);
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "browser_history");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn non_browser_sqlite_attaches_as_plain_file() -> Result<()> {
        let case_path = unique_case_path("non-browser-sqlite-attach");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("non-browser-sqlite-source");
        let sqlite_path = evidence_dir.join("notes.sqlite");
        Connection::open(&sqlite_path)?
            .execute_batch("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT);")?;

        assert_eq!(detect_browser_database(&sqlite_path)?, None);
        let corrupt_path = evidence_dir.join("corrupt.sqlite");
        fs::write(&corrupt_path, b"SQLite format 3\0not a valid database")?;
        assert_eq!(detect_browser_database(&corrupt_path)?, None);
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: sqlite_path,
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].id, evidence_id);
        assert_eq!(evidence[0].source_kind, "file");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn non_sqlite_raw_file_keeps_image_attach_path() -> Result<()> {
        let case_path = unique_case_path("non-sqlite-raw-attach");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("non-sqlite-raw-source");
        let raw_path = evidence_dir.join("disk.raw");
        fs::write(&raw_path, b"not a sqlite database; raw media bytes")?;

        assert_eq!(detect_browser_database(&raw_path)?, None);
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: raw_path,
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].id, evidence_id);
        assert_eq!(evidence[0].source_kind, "image");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_attach_rejects_duplicate_source_path() -> Result<()> {
        let case_path = unique_case_path("duplicate-evidence");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("duplicate-evidence-source");
        fs::write(evidence_dir.join("sample.txt"), b"small sample")?;
        let options = || AddEvidenceOptions {
            path: evidence_dir.clone(),
            kind: EvidenceKind::Auto,
            read_file_system_requested: false,
            notes: None,
        };

        add_evidence(&case_path, options())?;
        let err = add_evidence(&case_path, options())
            .expect_err("duplicate evidence source should be rejected")
            .to_string();
        assert!(err.contains("evidence source already attached"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn remove_evidence_deletes_source_jobs_and_entries() -> Result<()> {
        let case_path = unique_case_path("remove-evidence");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("remove-evidence-source");
        fs::write(evidence_dir.join("note.txt"), b"case note")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert_eq!(
            list_filesystem_entries(&case_path, Some(evidence_id))?.len(),
            1
        );

        let removed = remove_evidence(&case_path, evidence_id)?;
        assert_eq!(removed.evidence_id, evidence_id);
        assert_eq!(removed.removed_entries, 1);
        assert_eq!(removed.removed_jobs, 1);
        assert!(list_evidence(&case_path)?.is_empty());
        assert!(list_filesystem_entries(&case_path, None)?.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn host_from_url_limits_at_sign_to_authority() {
        assert_eq!(
            host_from_url(
                "https://www.google.com/maps/place/X/@50.7371286,-2.049258912,15z/data=!3m1"
            ),
            "google.com"
        );
        assert_eq!(
            sanitize_logical_segment(&host_from_url(
                "https://www.google.com/maps/place/X/@50.7371286,-2.049258912,15z/data=!3m1"
            )),
            "google.com"
        );
        assert_eq!(
            host_from_url("https://user:pass@example.com/"),
            "example.com"
        );
        assert_eq!(host_from_url("example.com/@handle"), "example.com");
        assert_eq!(
            host_from_url("/maps/place/@50.7371286,-2.049258912,15z"),
            "unknown-host"
        );
    }

    #[test]
    fn sanitize_logical_segment_preserves_unix_dotfile_names() {
        assert_eq!(sanitize_logical_segment(".ssh"), ".ssh");
        assert_eq!(sanitize_logical_segment(".bashrc"), ".bashrc");
        assert_eq!(sanitize_logical_segment(".mozilla"), ".mozilla");
        assert_eq!(sanitize_logical_segment("config."), "config");
        assert_eq!(sanitize_logical_segment(".face.icon"), ".face.icon");
        assert_eq!(sanitize_logical_segment("."), "unnamed");
        assert_eq!(sanitize_logical_segment(".."), "unnamed");
        assert_eq!(sanitize_logical_segment("Documents"), "Documents");
        assert_eq!(
            sanitize_logical_segment("Alpha/Beta\tGamma"),
            "Alpha_Beta_Gamma"
        );

        // Internal keys may sanitize, but distinct exact source names must
        // never collapse because punctuation, Unicode, or the 96-byte display
        // bound differs outside the retained prefix.
        let question = internal_source_segment("report?.txt");
        let hash = internal_source_segment("report#.txt");
        assert_ne!(question, hash);
        assert_eq!(question, internal_source_segment("report?.txt"));
        assert_ne!(
            internal_source_segment("résumé.txt"),
            internal_source_segment("rsum.txt")
        );
        let long_a = format!("{}A.txt", "x".repeat(110));
        let long_b = format!("{}B.txt", "x".repeat(110));
        assert_ne!(
            internal_source_segment(&long_a),
            internal_source_segment(&long_b)
        );
    }

    #[test]
    fn add_evidence_clears_stale_findings_from_empty_case() -> Result<()> {
        let case_path = unique_case_path("clear-stale-before-add");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Old hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;
        assert_eq!(list_bookmarks(&case_path)?.len(), 1);

        let evidence_dir = unique_temp_dir("clear-stale-before-add-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert!(list_bookmark_folders(&case_path)?.is_empty());
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(list_bookmark_items(&case_path, None)?.is_empty());
        assert!(report_data(&case_path)?.folders.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn unindexed_case_cleanup_preserves_current_evidence_source_bookmark() -> Result<()> {
        let case_path = unique_case_path("clear-stale-preserve-current");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-stale-preserve-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let stale_folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let stale_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(stale_folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: stale_bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Old hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;
        let current_folder_id = create_bookmark_folder(&case_path, None, "Evidence", None, true)?;
        let current_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(current_folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: current_bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("Current source".to_string()),
                logical_path: Some(evidence_dir.to_string_lossy().into_owned()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "evidence_source" }),
            },
        )?;

        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);

        let bookmarks = list_bookmarks(&case_path)?;
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].id, current_bookmark_id);
        let items = list_bookmark_items(&case_path, None)?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].evidence_id, Some(evidence_id));
        assert_eq!(report_data(&case_path)?.folders.len(), 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn stale_cleanup_preserves_parent_of_valid_nested_finding() -> Result<()> {
        let case_path = unique_case_path("clear-stale-preserve-nested");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-stale-preserve-nested-source");
        fs::write(evidence_dir.join("note.txt"), b"nested finding")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.entry_kind == "file")
            .expect("indexed file entry");
        let parent_id = create_bookmark_folder(&case_path, None, "Parent", None, true)?;
        let child_id = create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(child_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(entry.id),
                item_order: None,
                display_name: Some(entry.name),
                logical_path: Some(entry.logical_path),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "filesystem_entry" }),
            },
        )?;

        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_folders, 0);
        assert_eq!(cleared.removed_bookmarks, 0);
        assert_eq!(cleared.removed_items, 0);
        let folder_ids = list_bookmark_folders(&case_path)?
            .into_iter()
            .map(|folder| folder.id)
            .collect::<HashSet<_>>();
        assert!(folder_ids.contains(&parent_id));
        assert!(folder_ids.contains(&child_id));
        assert_eq!(list_bookmarks(&case_path)?.len(), 1);
        assert_eq!(list_bookmark_items(&case_path, None)?.len(), 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn stale_orphan_findings_are_cleared_after_entries_exist() -> Result<()> {
        let case_path = unique_case_path("clear-stale-after-index");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-stale-after-index-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        let folder_id = create_bookmark_folder(&case_path, None, "Old Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Orphan hit".to_string()),
                logical_path: Some("/old/path.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "stale" }),
            },
        )?;

        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(report_data(&case_path)?.folders.is_empty());
        assert!(filesystem_entry_count(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn reprocess_relinks_bookmark_items_by_logical_path() -> Result<()> {
        let case_path = unique_case_path("reprocess-relink-bookmarks");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("reprocess-relink-source");
        fs::write(evidence_dir.join("keep.txt"), b"keep me")?;
        fs::write(evidence_dir.join("gone.txt"), b"i will vanish")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, None)?;
        let keep_entry = entries
            .iter()
            .find(|entry| entry.name == "keep.txt")
            .expect("keep.txt indexed");
        let gone_entry = entries
            .iter()
            .find(|entry| entry.name == "gone.txt")
            .expect("gone.txt indexed");
        let keep_path = keep_entry.logical_path.clone();
        let gone_path = gone_entry.logical_path.clone();

        let folder_id = create_bookmark_folder(&case_path, None, "Findings", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        for entry in [keep_entry, gone_entry] {
            add_bookmark_item(
                &case_path,
                CreateBookmarkItemOptions {
                    bookmark_id,
                    evidence_id: Some(evidence_id),
                    entry_id: Some(entry.id),
                    item_order: None,
                    display_name: Some(entry.name.clone()),
                    logical_path: Some(entry.logical_path.clone()),
                    selection_offset: None,
                    selection_length: None,
                    data_preview: None,
                    item_ref_json: serde_json::json!({ "kind": "file" }),
                },
            )?;
        }

        // Image evidence reprocessing deletes all of the source's entries before re-indexing,
        // which nulls bookmark item entry links through the foreign key. Folder evidence upserts
        // in place, so simulate the image delete here to exercise the re-link path.
        {
            let conn = open_existing_case(&case_path)?;
            let case_id = active_case_id(&conn)?;
            conn.execute(
                "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
                params![case_id, evidence_id],
            )?;
        }
        for item in list_bookmark_items(&case_path, None)? {
            assert_eq!(item.entry_id, None, "delete must null bookmark entry links");
        }

        fs::remove_file(evidence_dir.join("gone.txt"))?;
        let result = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        assert_eq!(result.bookmark_items_relinked, 1);

        let new_entries = list_filesystem_entries(&case_path, None)?;
        let new_keep = new_entries
            .iter()
            .find(|entry| entry.logical_path == keep_path)
            .expect("keep.txt reindexed");
        let items = list_bookmark_items(&case_path, None)?;
        assert_eq!(items.len(), 2);
        let keep_item = items
            .iter()
            .find(|item| item.logical_path.as_deref() == Some(keep_path.as_str()))
            .expect("keep.txt bookmark item");
        assert_eq!(keep_item.entry_id, Some(new_keep.id));
        let gone_item = items
            .iter()
            .find(|item| item.logical_path.as_deref() == Some(gone_path.as_str()))
            .expect("gone.txt bookmark item");
        assert_eq!(gone_item.entry_id, None);

        // Re-linked and evidence-bound items must both survive the stale-findings cleanup.
        let cleared = clear_stale_findings(&case_path)?;
        assert_eq!(cleared.removed_items, 0);
        assert_eq!(cleared.removed_bookmarks, 0);
        assert_eq!(list_bookmark_items(&case_path, None)?.len(), 2);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn clear_all_findings_removes_valid_current_bookmarks_on_request() -> Result<()> {
        let case_path = unique_case_path("clear-all-findings");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("clear-all-findings-source");
        fs::write(evidence_dir.join("note.txt"), b"fresh")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;
        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.entry_kind == "file")
            .expect("indexed file entry should exist");
        let folder_id = create_bookmark_folder(&case_path, None, "Evidence Entries", None, true)?;
        let bookmark_id = create_bookmark(&case_path, test_bookmark_options(folder_id))?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(entry.id),
                item_order: None,
                display_name: Some(entry.name),
                logical_path: Some(entry.logical_path),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({ "kind": "filesystem_entry" }),
            },
        )?;

        let cleared = clear_all_findings(&case_path)?;
        assert_eq!(cleared.removed_bookmarks, 1);
        assert_eq!(cleared.removed_items, 1);
        assert!(list_bookmark_folders(&case_path)?.is_empty());
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(list_bookmark_items(&case_path, None)?.is_empty());
        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert!(filesystem_entry_count(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn pst_filetime_to_rfc3339_converts_known_reference_values() {
        // Windows FILETIME epoch is 1601-01-01; the constant below is exactly the number of
        // 100ns intervals between 1601-01-01 and the Unix epoch (1970-01-01), i.e. filetime 0
        // maps to the FILETIME epoch itself and this value maps to the Unix epoch.
        assert_eq!(
            pst_filetime_to_rfc3339(116_444_736_000_000_000),
            Some("1970-01-01T00:00:00+00:00".to_string())
        );
        // 132223104000000000 is the well-known FILETIME reference value for 2020-01-01T00:00:00Z
        // ((1577836800 unix seconds + 11644473600 epoch offset) * 10_000_000).
        assert_eq!(
            pst_filetime_to_rfc3339(132_223_104_000_000_000),
            Some("2020-01-01T00:00:00+00:00".to_string())
        );
        assert_eq!(
            pst_filetime_to_rfc3339(0),
            Some("1601-01-01T00:00:00+00:00".to_string())
        );
    }

    #[test]
    fn detect_pst_header_classifies_unicode_ansi_and_unsupported_variants() -> Result<()> {
        let dir = unique_temp_dir("pst-header-detect");

        let mut unicode_header = vec![0_u8; 12];
        unicode_header[0..4].copy_from_slice(b"!BDN");
        unicode_header[8..10].copy_from_slice(b"SM");
        unicode_header[10..12].copy_from_slice(&23_u16.to_le_bytes());
        let unicode_path = dir.join("unicode.pst");
        fs::write(&unicode_path, &unicode_header)?;
        let unicode_status = detect_pst_header(&unicode_path)?;
        assert_eq!(unicode_status.kind, PstHeaderKind::Unicode { version: 23 });
        assert_eq!(unicode_status.status, "parsed");
        assert_eq!(unicode_status.client_signature.as_deref(), Some("SM"));
        assert_eq!(unicode_status.classification, "unicode-classic-v23");
        assert_eq!(unicode_status.page_size_bytes, Some(512));
        assert!(unicode_status.native_supported);

        let mut ost_header = unicode_header.clone();
        ost_header[8..10].copy_from_slice(b"SO");
        let ost_path = dir.join("unicode.ost");
        fs::write(&ost_path, &ost_header)?;
        let ost_status = detect_pst_header(&ost_path)?;
        assert_eq!(ost_status.kind, PstHeaderKind::Unicode { version: 23 });
        assert_eq!(ost_status.client_signature.as_deref(), Some("SO"));
        assert_eq!(ost_status.classification, "unicode-classic-v23");

        let mut ansi_header = vec![0_u8; 12];
        ansi_header[0..4].copy_from_slice(b"!BDN");
        ansi_header[8..10].copy_from_slice(b"SM");
        ansi_header[10..12].copy_from_slice(&14_u16.to_le_bytes());
        let ansi_path = dir.join("ansi.pst");
        fs::write(&ansi_path, &ansi_header)?;
        let ansi_status = detect_pst_header(&ansi_path)?;
        assert_eq!(ansi_status.kind, PstHeaderKind::Ansi { version: 14 });
        assert!(ansi_status.reason.is_none());

        let mut unicode_4k_header = unicode_header.clone();
        unicode_4k_header[10..12].copy_from_slice(&36_u16.to_le_bytes());
        let unicode_4k_path = dir.join("unicode-4k.ost");
        fs::write(&unicode_4k_path, &unicode_4k_header)?;
        let unicode_4k_status = detect_pst_header(&unicode_4k_path)?;
        assert_eq!(unicode_4k_status.kind, PstHeaderKind::Unsupported);
        assert_eq!(unicode_4k_status.status, "unsupported_variant");
        assert_eq!(unicode_4k_status.classification, "unicode-4k-v36");
        assert_eq!(unicode_4k_status.page_size_bytes, Some(4096));
        assert!(!unicode_4k_status.native_supported);
        assert_eq!(
            failed_mailbox_attempt_status(Some(&unicode_status)),
            "failed"
        );
        assert_eq!(
            failed_mailbox_attempt_status(Some(&unicode_4k_status)),
            "unsupported_variant"
        );
        assert_eq!(failed_mailbox_attempt_status(None), "failed");

        let wrong_magic_path = dir.join("wrong-magic.pst");
        fs::write(&wrong_magic_path, b"NOTAPSTFILE!")?;
        let wrong_magic_status = detect_pst_header(&wrong_magic_path)?;
        assert_eq!(wrong_magic_status.kind, PstHeaderKind::Unsupported);
        assert_eq!(wrong_magic_status.status, "not_pff");
        assert_eq!(wrong_magic_status.classification, "not-pff");
        assert!(wrong_magic_status
            .reason
            .unwrap_or_default()
            .contains("magic"));

        let short_path = dir.join("short.pst");
        fs::write(&short_path, b"short")?;
        let short_status = detect_pst_header(&short_path)?;
        assert_eq!(short_status.kind, PstHeaderKind::Unsupported);
        assert_eq!(short_status.status, "truncated_header");
        assert!(short_status
            .reason
            .unwrap_or_default()
            .contains("shorter than 12 bytes"));

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn partial_mailbox_reprocessing_preserves_prior_committed_rows() {
        let complete = pst::PstTelemetry::default();
        assert!(!should_preserve_prior_mailbox_reprocess(1, &complete));

        let mut parser_partial = complete.clone();
        parser_partial.status = pst::PstStatus::Partial;
        assert!(should_preserve_prior_mailbox_reprocess(1, &parser_partial));
        assert!(!should_preserve_prior_mailbox_reprocess(0, &parser_partial));

        let mut limited = complete;
        limited.message_limit_reached = true;
        assert!(should_preserve_prior_mailbox_reprocess(1, &limited));
        assert!(!should_preserve_prior_mailbox_reprocess(0, &limited));
    }

    #[test]
    fn mark_email_store_routes_only_pff_compatible_mailboxes_to_native_parsing() {
        for extension in ["pst", "ost", "nst"] {
            let mut metadata = serde_json::json!({});
            mark_email_store(&mut metadata, extension);
            assert_eq!(metadata["artifact_kind"].as_str(), Some("email_store"));
            assert_eq!(metadata["email_format"].as_str(), Some(extension));
            assert_eq!(metadata["email_parser_status"].as_str(), Some("pending"));
            assert!(metadata.get("email_parser_error").is_none());
        }

        for extension in ["msg", "mbox", "olm", "dbx", "nsf"] {
            let mut metadata = serde_json::json!({});
            mark_email_store(&mut metadata, extension);
            assert_eq!(metadata["email_parser_status"].as_str(), Some("skipped"));
            assert!(metadata["email_parser_error"]
                .as_str()
                .is_some_and(|reason| reason.contains("available for export")));
        }
    }

    #[test]
    fn pst_sqlite_sink_streams_full_body_and_attachment_payload() -> Result<()> {
        let case_path = unique_case_path("pst-sqlite-sink");
        create_test_case(&case_path)?;
        let source_dir = unique_temp_dir("pst-sqlite-source");
        let source_path = source_dir.join("mailbox.pst");
        fs::write(&source_path, b"test-only source placeholder")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: source_path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let mut conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json)
             VALUES (?1, ?2, 'pst-test', 'running', '{}')",
            params![case_id, evidence_id],
        )?;
        let job_id = tx.last_insert_rowid();
        let exact_source_path = "Volume 1/Users/Alice/Outlook/Mailbox.PST";
        let mut sink = PstSqliteSink::new(
            &tx,
            case_id,
            evidence_id,
            job_id,
            "/Mailbox".to_string(),
            "Mailbox.PST",
            None,
            "pst",
            exact_source_path,
            None,
        )?;
        pst::PstStreamSink::on_folder(
            &mut sink,
            &pst::PstFolderInfo {
                node_id: 1,
                display_name: "Inbox".to_string(),
                path: "Mailbox/Inbox".to_string(),
                subfolder_count: 0,
                content_count: 1,
                unread_count: 0,
            },
        )?;
        pst::PstStreamSink::on_message_header(
            &mut sink,
            &pst::PstMessageHeader {
                node_id: 2,
                entry_id_hex: "0x00000002".to_string(),
                folder_path: "Mailbox/Inbox".to_string(),
                message_class: "IPM.Note".to_string(),
                subject: Some("Gold mailbox test".to_string()),
                sender_name: Some("Alice".to_string()),
                sender_email: Some("alice@example.test".to_string()),
                client_submit_time: None,
                delivery_time: None,
                creation_time: None,
                last_modification_time: None,
                body_plain_preview: Some("preview".to_string()),
                body_html_preview: None,
                body_plain_truncated: true,
                body_html_truncated: false,
                recipient_count: 1,
                attachment_count: 1,
                has_attachments: true,
                message_flags: 1,
                internet_code_page: Some(1252),
            },
        )?;
        let mut full_body = vec![b'A'; 70_000];
        full_body.extend_from_slice(b"-TAIL");
        pst::PstStreamSink::on_message_body(
            &mut sink,
            "Mailbox/Inbox",
            2,
            pst::PstBodyKind::PlainText,
            pst::PstTextRef::String8(&full_body, Some(1252)),
        )?;
        pst::PstStreamSink::on_recipient(
            &mut sink,
            "Mailbox/Inbox",
            2,
            &pst::PstRecipientInfo {
                display_name: Some("Bob".to_string()),
                email_address: Some("bob@example.test".to_string()),
                recipient_type: Some("to".to_string()),
            },
        )?;
        let attachment_name = "Quarterly report: final?.pdf";
        let attachment = pst::PstAttachmentInfo {
            attachment_index: 0,
            filename: Some(attachment_name.to_string()),
            mime_type: Some("application/pdf".to_string()),
            size_bytes: 8,
            is_embedded_message: false,
            content_id: Some("cid-1".to_string()),
            is_skipped: false,
        };
        pst::PstStreamSink::on_attachment_header(&mut sink, "Mailbox/Inbox", 2, &attachment)?;
        let attachment_bytes = b"PDF-BYTES";
        pst::PstStreamSink::on_attachment_bytes(
            &mut sink,
            "Mailbox/Inbox",
            2,
            &attachment,
            attachment_bytes,
        )?;
        drop(sink);
        tx.commit()?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let message = entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"] == "email_message")
            .context("PST message entry missing")?;
        assert_eq!(
            message.metadata_json["source_artifact_path"].as_str(),
            Some(exact_source_path)
        );
        let attachment_entry = entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"] == "email_attachment")
            .context("PST attachment entry missing")?;
        assert_eq!(attachment_entry.name, attachment_name);
        assert_eq!(
            attachment_entry.metadata_json["attachment_filename"].as_str(),
            Some(attachment_name)
        );
        assert!(attachment_entry
            .logical_path
            .ends_with(&sanitize_logical_segment(attachment_name)));
        assert_eq!(
            attachment_entry.metadata_json["attachment_sha256"].as_str(),
            Some(sha256_hex(attachment_bytes).as_str())
        );
        assert_eq!(
            attachment_entry.metadata_json["attachment_size_matches_declared"].as_bool(),
            Some(false)
        );

        let conn = open_existing_case(&case_path)?;
        let segments = {
            let mut stmt = conn.prepare(
                "SELECT content FROM filesystem_entry_text_segments
                 WHERE entry_id = ?1 AND parser_name = ?2 ORDER BY segment_index",
            )?;
            let rows = stmt.query_map(params![message.id, PST_PARSER_NAME], |row| {
                row.get::<_, Vec<u8>>(0)
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(segments.len(), 2);
        assert_eq!(segments.concat(), full_body);
        drop(conn);

        let window = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: attachment_entry.id,
                offset: 2,
                length: 4,
            },
        )?;
        assert_eq!(window.bytes, b"F-BY");
        assert_eq!(window.total_size, attachment_bytes.len() as u64);

        let conn = open_existing_case(&case_path)?;
        conn.execute(
            "DELETE FROM filesystem_entries WHERE id = ?1",
            params![attachment_entry.id],
        )?;
        let blobs_remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM filesystem_entry_binary_blobs WHERE entry_id = ?1",
            params![attachment_entry.id],
            |row| row.get(0),
        )?;
        assert_eq!(blobs_remaining, 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn detect_registry_hive_header_classifies_valid_and_invalid_files() -> Result<()> {
        let dir = unique_temp_dir("registry-header-detect");

        let valid_path = dir.join("NTUSER.DAT");
        let mut valid_bytes = vec![0_u8; 32];
        valid_bytes[0..4].copy_from_slice(b"regf");
        fs::write(&valid_path, &valid_bytes)?;
        assert_eq!(
            detect_registry_hive_header(&valid_path)?.kind,
            RegistryHiveHeaderKind::Regf
        );

        let wrong_magic_path = dir.join("wrong-magic.dat");
        fs::write(&wrong_magic_path, b"NOTAHIVE")?;
        let wrong_magic_status = detect_registry_hive_header(&wrong_magic_path)?;
        assert_eq!(wrong_magic_status.kind, RegistryHiveHeaderKind::Unsupported);
        assert!(wrong_magic_status
            .reason
            .unwrap_or_default()
            .contains("regf"));

        let short_path = dir.join("short.dat");
        fs::write(&short_path, b"re")?;
        let short_status = detect_registry_hive_header(&short_path)?;
        assert_eq!(short_status.kind, RegistryHiveHeaderKind::Unsupported);
        assert!(short_status
            .reason
            .unwrap_or_default()
            .contains("shorter than 4 bytes"));

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn registry_render_value_formats_every_cell_value_variant() {
        let string_val = registry_render_value(
            RegistryValueDataType::REG_SZ,
            &RegistryCellValue::String("C:\\Windows\\notepad.exe\u{0}\u{0}".to_string()),
        );
        assert_eq!(string_val.text, "C:\\Windows\\notepad.exe");
        assert!(!string_val.truncated);

        let multi = registry_render_value(
            RegistryValueDataType::REG_MULTI_SZ,
            &RegistryCellValue::MultiString(vec!["one".to_string(), "two".to_string()]),
        );
        assert_eq!(multi.text, "one | two");
        assert_eq!(
            multi.items,
            Some(vec!["one".to_string(), "two".to_string()])
        );

        let binary_small = registry_render_value(
            RegistryValueDataType::REG_BIN,
            &RegistryCellValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        assert_eq!(binary_small.text, "DE AD BE EF");
        assert!(!binary_small.truncated);

        let big_bytes = vec![0xAB_u8; REGISTRY_BINARY_PREVIEW_BYTES + 10];
        let binary_big = registry_render_value(
            RegistryValueDataType::REG_BIN,
            &RegistryCellValue::Binary(big_bytes),
        );
        assert!(binary_big.truncated);
        assert!(binary_big.text.contains(&format!(
            "{} bytes total",
            REGISTRY_BINARY_PREVIEW_BYTES + 10
        )));

        let dword = registry_render_value(
            RegistryValueDataType::REG_DWORD,
            &RegistryCellValue::U32(305_419_896),
        );
        assert_eq!(dword.text, "305419896 (0x12345678)");

        // FILETIME rendering must append the decoded UTC timestamp, not just the raw integer -
        // this is the field examiners actually care about for a REG_FILETIME value.
        let filetime = registry_render_value(
            RegistryValueDataType::REG_FILETIME,
            &RegistryCellValue::U64(132_223_104_000_000_000),
        );
        assert!(filetime.text.contains("132223104000000000"));
        assert!(filetime.text.contains("2020-01-01T00:00:00+00:00"));

        let none_val =
            registry_render_value(RegistryValueDataType::REG_NONE, &RegistryCellValue::None);
        assert_eq!(none_val.text, "");

        let error_val =
            registry_render_value(RegistryValueDataType::REG_SZ, &RegistryCellValue::Error);
        assert!(error_val.text.contains("could not be decoded"));
    }

    #[test]
    fn registry_value_type_label_maps_common_types() {
        assert_eq!(
            registry_value_type_label(RegistryValueDataType::REG_SZ),
            "REG_SZ"
        );
        assert_eq!(
            registry_value_type_label(RegistryValueDataType::REG_DWORD),
            "REG_DWORD"
        );
        assert_eq!(
            registry_value_type_label(RegistryValueDataType::REG_BIN),
            "REG_BINARY"
        );
        assert_eq!(
            registry_value_type_label(RegistryValueDataType::REG_QWORD),
            "REG_QWORD"
        );
    }

    #[test]
    fn registry_path_helpers_build_stable_unique_paths() {
        assert_eq!(
            registry_root_logical_path("NTUSER.DAT"),
            "/Registry/NTUSER.DAT"
        );
        assert_eq!(
            registry_key_display_path("ROOT\\Software\\Microsoft\\Windows"),
            "ROOT\\Software\\Microsoft\\Windows"
        );
        assert_eq!(registry_key_display_path(""), "\\");

        let mut used = HashSet::new();
        let key_path = registry_key_logical_path(
            "/Registry/NTUSER.DAT",
            "ROOT\\Software\\Run",
            0x100,
            &mut used,
        );
        assert_eq!(key_path, "/Registry/NTUSER.DAT/ROOT/Software/Run");

        let value_path = registry_value_logical_path(&key_path, "OneDrive", 0x200, &mut used);
        assert_eq!(
            value_path,
            "/Registry/NTUSER.DAT/ROOT/Software/Run/OneDrive.value"
        );

        // Two keys that normalize to the same logical path (e.g. differing only by case/
        // whitespace quirks upstream) must not collide silently - the offset-based suffix keeps
        // both entries distinguishable and queryable.
        let colliding = registry_key_logical_path(
            "/Registry/NTUSER.DAT",
            "ROOT\\Software\\Run",
            0x300,
            &mut used,
        );
        assert_ne!(colliding, key_path);
        assert!(colliding.starts_with(&key_path));
    }

    fn write_registry_fixture(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = dir.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }

    #[test]
    fn standalone_usrclass_dat_dispatches_to_registry_parser() -> Result<()> {
        let case_path = unique_case_path("registry-usrclass-single-file");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("registry-usrclass-single-file-source");
        let path = write_registry_fixture(&dir, "USRCLASS.DAT", b"NOT-A-REGISTRY-HIVE")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata_json["artifact_kind"], "registry_hive");
        assert_eq!(
            entries[0].metadata_json["registry_parser_status"],
            "unsupported"
        );
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    fn synthetic_mft_record(record_number: u32, name: &str, in_use: bool) -> Vec<u8> {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&48_u16.to_le_bytes());
        record[6..8].copy_from_slice(&3_u16.to_le_bytes());
        record[16..18].copy_from_slice(&1_u16.to_le_bytes());
        record[20..22].copy_from_slice(&56_u16.to_le_bytes());
        record[22..24].copy_from_slice(&(if in_use { 1_u16 } else { 0 }).to_le_bytes());
        record[24..28].copy_from_slice(&256_u32.to_le_bytes());
        record[28..32].copy_from_slice(&1024_u32.to_le_bytes());
        record[44..48].copy_from_slice(&record_number.to_le_bytes());
        record[48..50].copy_from_slice(&0xAAAA_u16.to_le_bytes());
        record[50..52].copy_from_slice(&0_u16.to_le_bytes());
        record[52..54].copy_from_slice(&0_u16.to_le_bytes());
        record[510..512].copy_from_slice(&0xAAAA_u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xAAAA_u16.to_le_bytes());
        let name_utf16 = name.encode_utf16().collect::<Vec<_>>();
        let value_len = 66 + name_utf16.len() * 2;
        let attr_len = (24 + value_len + 7) & !7;
        let attr = 56;
        record[attr..attr + 4].copy_from_slice(&0x30_u32.to_le_bytes());
        record[attr + 4..attr + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[attr + 16..attr + 20].copy_from_slice(&(value_len as u32).to_le_bytes());
        record[attr + 20..attr + 22].copy_from_slice(&24_u16.to_le_bytes());
        let value = attr + 24;
        record[value..value + 8].copy_from_slice(&5_u64.to_le_bytes());
        record[value + 40..value + 48].copy_from_slice(&1234_u64.to_le_bytes());
        record[value + 48..value + 56].copy_from_slice(&4096_u64.to_le_bytes());
        record[value + 64] = name_utf16.len() as u8;
        record[value + 65] = 1;
        for (index, ch) in name_utf16.into_iter().enumerate() {
            let start = value + 66 + index * 2;
            record[start..start + 2].copy_from_slice(&ch.to_le_bytes());
        }
        record[attr + attr_len..attr + attr_len + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        record
    }

    #[test]
    fn standalone_mft_file_is_parsed_into_records() -> Result<()> {
        let case_path = unique_case_path("standalone-mft");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("standalone-mft-source");
        // Export tools commonly prefix the NTFS metadata filename with a volume label.
        let path = dir.join("live-vol1-$MFT");
        let mut bytes = synthetic_mft_record(0, "$MFT", true);
        bytes.extend(synthetic_mft_record(1, "deleted.txt", false));
        fs::write(&path, bytes)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|entry| entry.name == "$MFT" && !entry.is_deleted));
        let deleted = entries
            .iter()
            .find(|entry| entry.name == "deleted.txt")
            .unwrap();
        assert!(deleted.is_deleted);
        assert_eq!(deleted.size_bytes, Some(1234));
        assert_eq!(
            deleted.metadata_json["filesystem_parser"],
            "mft crate 0.7.0"
        );
        assert_eq!(
            deleted.metadata_json["virtual_filesystem"],
            "standalone_mft_reconstruction"
        );
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_registry_hive_evidence_reports_wrong_magic_as_unsupported() -> Result<()> {
        let case_path = unique_case_path("registry-wrong-magic");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("registry-wrong-magic-source");
        let path = write_registry_fixture(&dir, "NTUSER.DAT", b"NOT-A-REGISTRY-HIVE-AT-ALL")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .into_iter()
            .next()
            .expect("registry evidence should produce at least one entry");
        assert_eq!(
            entry.metadata_json["artifact_kind"].as_str(),
            Some("registry_hive")
        );
        assert_eq!(
            entry.metadata_json["registry_parser_status"].as_str(),
            Some("unsupported")
        );
        assert!(entry.metadata_json["registry_parser_error"]
            .as_str()
            .unwrap_or_default()
            .contains("regf"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_registry_hive_evidence_reports_corrupt_regf_gracefully() -> Result<()> {
        // A file that passes the cheap 4-byte "regf" magic sniff but is not a structurally valid
        // hive. notatin cannot open it, and process_registry_hive_evidence must fall back to the
        // same "detected, not parsed" status used elsewhere rather than crashing or hanging.
        let case_path = unique_case_path("registry-corrupt-regf");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("registry-corrupt-regf-source");
        let mut bytes = vec![0_u8; 512];
        bytes[0..4].copy_from_slice(b"regf");
        let path = write_registry_fixture(&dir, "SOFTWARE", &bytes)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .into_iter()
            .next()
            .expect("registry evidence should produce at least one entry");
        assert_eq!(
            entry.metadata_json["registry_parser_status"].as_str(),
            Some("unsupported")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn evtx_level_label_maps_known_and_unknown_codes() {
        assert_eq!(
            evtx_level_label(Some(0), None),
            Some("Information".to_string())
        );
        assert_eq!(
            evtx_level_label(Some(1), None),
            Some("Critical".to_string())
        );
        assert_eq!(evtx_level_label(Some(2), None), Some("Error".to_string()));
        assert_eq!(evtx_level_label(Some(3), None), Some("Warning".to_string()));
        assert_eq!(
            evtx_level_label(Some(4), None),
            Some("Information".to_string())
        );
        assert_eq!(evtx_level_label(Some(5), None), Some("Verbose".to_string()));
        assert_eq!(
            evtx_level_label(Some(99), None),
            Some("Unknown (99)".to_string())
        );
        assert_eq!(
            evtx_level_label(None, Some("Custom")),
            Some("Custom".to_string())
        );
        assert_eq!(evtx_level_label(None, None), None);
    }

    #[test]
    fn evtx_channel_hint_decodes_windows_percent_encoding() {
        assert_eq!(
            evtx_channel_hint("Microsoft-Windows-TaskScheduler%4Operational.evtx"),
            Some("Microsoft-Windows-TaskScheduler/Operational".to_string())
        );
        assert_eq!(
            evtx_channel_hint("Security.evtx"),
            Some("Security".to_string())
        );
    }

    #[test]
    fn evtx_json_path_helpers_navigate_and_coerce() {
        let system = serde_json::json!({
            "EventID": 4624,
            "Level": "4",
            "Nested": { "#text": "778" }
        });
        assert_eq!(evtx_json_path_u64(&system, &["EventID"]), Some(4624));
        assert_eq!(
            evtx_json_path_string(&system, &["Level"]),
            Some("4".to_string())
        );
        assert_eq!(evtx_scalar_u64(&system["Nested"]), Some(778));
        assert_eq!(evtx_json_path_u64(&system, &["Missing"]), None);
    }

    #[test]
    fn evtx_find_user_sid_prefers_known_fields_and_recurses() {
        let event = serde_json::json!({
            "EventData": {
                "SubjectUserSid": "S-1-5-21-111-222-333-1001",
                "TargetUserName": "alice"
            }
        });
        assert_eq!(
            evtx_find_user_sid(&event),
            Some("S-1-5-21-111-222-333-1001".to_string())
        );
        assert_eq!(evtx_find_user_name(&event), Some("alice".to_string()));
        assert_eq!(
            evtx_find_user_sid(&serde_json::json!({"x": "not-a-sid"})),
            None
        );
        assert_eq!(
            evtx_provider_guid(&serde_json::json!({
                "Provider": {"#attributes": {"Guid": "{ABC}", "Name": "Source"}}
            })),
            Some("{ABC}".to_string())
        );
    }

    #[test]
    fn evtx_logical_path_helpers_build_stable_unique_paths() {
        assert_eq!(
            evtx_root_logical_path("Security.evtx"),
            "/Event Logs/Security.evtx"
        );
        let first = evtx_record_logical_path("/Event Logs/Security.evtx", 42, 1);
        assert_eq!(
            first,
            "/Event Logs/Security.evtx/00000000000000000001-42.record"
        );
        let second = evtx_record_logical_path("/Event Logs/Security.evtx", 42, 2);
        assert_ne!(second, first);
        assert_eq!(
            second,
            "/Event Logs/Security.evtx/00000000000000000002-42.record"
        );
    }

    #[test]
    fn process_evtx_event_log_evidence_reports_corrupt_file_gracefully() -> Result<()> {
        // Not a valid EVTX container at all (real EVTX files start with an "ElfFile\0" magic) -
        // the evtx crate must fail to open it, and process_evtx_event_log_evidence must fall back
        // to the same "detected, not parsed" status used by every other parser in this codebase
        // rather than crashing or hanging.
        let case_path = unique_case_path("evtx-corrupt");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("evtx-corrupt-source");
        let path = dir.join("Application.evtx");
        fs::write(&path, b"NOT-A-VALID-EVTX-FILE-AT-ALL")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "truncated");
        assert!(processed.truncated);
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .into_iter()
            .next()
            .expect("EVTX evidence should produce at least one entry");
        assert_eq!(
            entry.metadata_json["artifact_kind"].as_str(),
            Some("evtx_log")
        );
        assert_eq!(
            entry.metadata_json["evtx_parser_status"].as_str(),
            Some("unsupported")
        );
        assert!(entry.metadata_json["evtx_parser_error"]
            .as_str()
            .unwrap_or_default()
            .contains("could not"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_evtx_empty_valid_header_is_explicitly_complete() -> Result<()> {
        let case_path = unique_case_path("evtx-empty-valid");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("evtx-empty-valid-source");
        let path = dir.join("Empty.evtx");
        let mut bytes = vec![0_u8; 4096];
        bytes[0..8].copy_from_slice(b"ElfFile\0");
        bytes[32..36].copy_from_slice(&128_u32.to_le_bytes());
        bytes[36..38].copy_from_slice(&1_u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&3_u16.to_le_bytes());
        bytes[40..42].copy_from_slice(&4096_u16.to_le_bytes());
        fs::write(&path, bytes)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(!processed.truncated);
        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .next()
            .expect("valid empty EVTX should produce its root row");
        assert_eq!(entry.metadata_json["evtx_parser_status"], "parsed");
        assert_eq!(entry.metadata_json["evtx_records_seen"], 0);
        assert_eq!(entry.metadata_json["evtx_parser_error_count"], 0);
        assert_eq!(entry.metadata_json["evtx_empty_valid_log"], true);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn has_chromium_blockfile_cache_layout_requires_index_and_data_file() -> Result<()> {
        let dir = unique_temp_dir("chrome-cache-layout-detect");

        let empty_dir = dir.join("empty");
        fs::create_dir_all(&empty_dir)?;
        assert!(!has_chromium_blockfile_cache_layout(&empty_dir));

        let index_only = dir.join("index-only");
        fs::create_dir_all(&index_only)?;
        fs::write(index_only.join("index"), b"idx")?;
        assert!(!has_chromium_blockfile_cache_layout(&index_only));

        let data_only = dir.join("data-only");
        fs::create_dir_all(&data_only)?;
        fs::write(data_only.join("data_0"), b"blk")?;
        assert!(!has_chromium_blockfile_cache_layout(&data_only));

        let real_cache = dir.join("real-cache");
        fs::create_dir_all(&real_cache)?;
        fs::write(real_cache.join("index"), b"idx")?;
        fs::write(real_cache.join("data_1"), b"blk")?;
        assert!(has_chromium_blockfile_cache_layout(&real_cache));

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn chrome_cache_effective_max_entries_preserves_unlimited_semantics() {
        assert_eq!(chrome_cache_effective_max_entries(0), usize::MAX);
        assert_eq!(chrome_cache_effective_max_entries(usize::MAX), usize::MAX);
        assert_eq!(chrome_cache_effective_max_entries(250), 250);
    }

    #[test]
    fn parse_chrome_cache_http_metadata_extracts_status_and_headers() {
        let raw = b"HTTP/1.1 200 OK\0Content-Type: text/html; charset=utf-8\0Cache-Control: max-age=3600\0ETag: \"abc123\"\0\0garbage-after-blank-line";
        let parsed = parse_chrome_cache_http_metadata(raw);
        assert_eq!(parsed.status_line.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(parsed.status_code, Some(200));
        assert_eq!(
            chrome_cache_header_value(&parsed.headers, "content-type").as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            chrome_cache_header_value(&parsed.headers, "Cache-Control").as_deref(),
            Some("max-age=3600")
        );
        assert_eq!(
            chrome_cache_header_value(&parsed.headers, "missing-header"),
            None
        );

        let empty = parse_chrome_cache_http_metadata(b"");
        assert_eq!(empty.status_line, None);
        assert!(empty.headers.is_empty());
    }

    #[test]
    fn chrome_cache_entry_state_label_maps_all_variants() {
        assert_eq!(
            chrome_cache_entry_state_label(BlockCacheEntryState::Normal),
            "normal"
        );
        assert_eq!(
            chrome_cache_entry_state_label(BlockCacheEntryState::Evicted),
            "evicted"
        );
        assert_eq!(
            chrome_cache_entry_state_label(BlockCacheEntryState::Doomed),
            "doomed"
        );
        assert_eq!(
            chrome_cache_entry_state_label(BlockCacheEntryState::Unknown),
            "unknown"
        );
    }

    #[test]
    fn chrome_cache_logical_path_helpers_build_stable_unique_paths() {
        assert_eq!(
            chrome_cache_root_logical_path("Cache"),
            "/Browser Cache/Cache"
        );
        let mut used = HashSet::new();
        let first = chrome_cache_entry_logical_path(
            "/Browser Cache/Cache",
            "example.com",
            "DEADBEEF",
            5,
            &mut used,
        );
        assert_eq!(
            first,
            "/Browser Cache/Cache/example.com/00000005-DEADBEEF.record"
        );
        let second = chrome_cache_entry_logical_path(
            "/Browser Cache/Cache",
            "example.com",
            "DEADBEEF",
            5,
            &mut used,
        );
        assert_ne!(second, first);
        assert!(second.starts_with(&first[..first.len() - ".record".len()]));
    }

    #[test]
    fn process_chromium_blockfile_cache_evidence_reports_corrupt_index_gracefully() -> Result<()> {
        // A directory with the right FILE NAMES (index + data_0) but no valid blockfile content -
        // the chrome-cache-parser crate must fail to open it, and this must fall back to the same
        // "detected, not parsed" status used by every other parser in this codebase rather than
        // crashing or hanging.
        let case_path = unique_case_path("chrome-cache-corrupt");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("chrome-cache-corrupt-source");
        let cache_dir = dir.join("Cache");
        fs::create_dir_all(&cache_dir)?;
        fs::write(cache_dir.join("index"), b"NOT-A-VALID-BLOCKFILE-INDEX")?;
        fs::write(cache_dir.join("data_0"), b"NOT-A-VALID-DATA-BLOCK-FILE")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: cache_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .into_iter()
            .next()
            .expect("Chrome cache evidence should produce at least one entry");
        assert_eq!(
            entry.metadata_json["artifact_kind"].as_str(),
            Some("browser_cache_store")
        );
        assert_eq!(
            entry.metadata_json["browser_cache_parser_status"].as_str(),
            Some("unsupported")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn detect_volume_filesystem_at_recognizes_bitlocker_fve_signature() -> Result<()> {
        // Real BitLocker/FVE volumes carry "-FVE-FS-" at the exact byte offset (3) where a
        // plaintext NTFS volume carries its "NTFS    " OEM ID - this must be detected BEFORE
        // falling through to the 0x55AA MBR-signature/OEM-ID checks, and must never be
        // misidentified as a parseable NTFS/FAT volume (that would mean attempting to walk
        // encrypted bytes as a plaintext filesystem).
        let mut header = vec![0_u8; 512];
        header[3..11].copy_from_slice(BITLOCKER_FVE_SIGNATURE);
        header[510] = 0x55;
        header[511] = 0xAA;
        let mut cursor = std::io::Cursor::new(header);
        let detected = detect_volume_filesystem_at(&mut cursor, 0)?;
        assert_eq!(detected, Some(BITLOCKER_LOCKED_FILESYSTEM));

        // A real NTFS header (no FVE signature) must still be detected normally - this fix must
        // not have broken ordinary NTFS detection.
        let mut ntfs_header = vec![0_u8; 512];
        ntfs_header[3..11].copy_from_slice(b"NTFS    ");
        ntfs_header[510] = 0x55;
        ntfs_header[511] = 0xAA;
        let mut ntfs_cursor = std::io::Cursor::new(ntfs_header);
        assert_eq!(
            detect_volume_filesystem_at(&mut ntfs_cursor, 0)?,
            Some("NTFS")
        );
        Ok(())
    }

    fn bitlocker_test_entry(entry_type: u16, value_type: u16, data: &[u8]) -> Vec<u8> {
        let size = (8 + data.len()) as u16;
        let mut entry = Vec::with_capacity(usize::from(size));
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&entry_type.to_le_bytes());
        entry.extend_from_slice(&value_type.to_le_bytes());
        entry.extend_from_slice(&1u16.to_le_bytes());
        entry.extend_from_slice(data);
        entry
    }

    fn bitlocker_metadata_only_image(method: u16, protectors: &[u16]) -> Vec<u8> {
        let metadata_offset = 0x1000_u64;
        let mut entries = Vec::new();
        for protector in protectors {
            let mut vmk = vec![0_u8; 28];
            vmk[26..28].copy_from_slice(&protector.to_le_bytes());
            entries.extend_from_slice(&bitlocker_test_entry(0x0002, 0x0008, &vmk));
        }
        let metadata_size = 48 + entries.len();
        let mut image = vec![0_u8; 0x2000];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(BITLOCKER_FVE_SIGNATURE);
        image[11..13].copy_from_slice(&512_u16.to_le_bytes());
        image[176..184].copy_from_slice(&metadata_offset.to_le_bytes());

        let mb = metadata_offset as usize;
        image[mb..mb + 8].copy_from_slice(BITLOCKER_FVE_SIGNATURE);
        image[mb + 32..mb + 40].copy_from_slice(&metadata_offset.to_le_bytes());
        image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
        image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&method.to_le_bytes());
        image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);
        image
    }

    #[test]
    fn list_image_volumes_surfaces_bitlocker_metadata_summary() -> Result<()> {
        let evidence_dir = unique_temp_dir("bitlocker-live-summary");
        let image_path = evidence_dir.join("locked.img");
        fs::write(
            &image_path,
            bitlocker_metadata_only_image(0x8002, &[0x0100]),
        )?;

        let volumes = list_image_volumes(&image_path)?;
        assert_eq!(volumes.len(), 1);
        let volume = &volumes[0];
        assert_eq!(volume.filesystem, BITLOCKER_LOCKED_FILESYSTEM);
        assert!(!volume.browsable);
        let bitlocker = volume
            .bitlocker
            .as_ref()
            .expect("locked volume should include BitLocker inspection summary");
        assert_eq!(bitlocker.metadata_state, "parsed");
        assert_eq!(bitlocker.variant, "Windows 7 or later");
        assert_eq!(bitlocker.encryption_method.as_deref(), Some("AES-128-CBC"));
        assert_eq!(bitlocker.encryption_method_raw.as_deref(), Some("0x8002"));
        assert_eq!(bitlocker.protectors.len(), 1);
        assert_eq!(bitlocker.protectors[0].kind, "TPM");
        assert!(bitlocker.tpm_only);
        assert_eq!(
            bitlocker.status,
            "BitLocker volume detected; cannot decrypt without recovery key/password"
        );

        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    fn write_pst_fixture(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = dir.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }

    fn pst_evidence_entry(case_path: &Path, path: PathBuf) -> Result<FilesystemEntry> {
        let evidence_id = add_evidence(
            case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(case_path, Some(evidence_id))?;
        Ok(entries
            .into_iter()
            .next()
            .expect("mailbox evidence should produce at least one entry"))
    }

    #[test]
    fn process_pst_mailbox_evidence_reports_wrong_magic_as_not_pff() -> Result<()> {
        let case_path = unique_case_path("pst-wrong-magic");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("pst-wrong-magic-source");
        let path = write_pst_fixture(&dir, "mail.pst", b"NOT-A-PST-FILE-AT-ALL")?;

        let entry = pst_evidence_entry(&case_path, path)?;
        assert_eq!(
            entry.metadata_json["artifact_kind"].as_str(),
            Some("email_store")
        );
        assert_eq!(
            entry.metadata_json["email_parser_status"].as_str(),
            Some("not_pff")
        );
        assert_eq!(entry.metadata_json["pst_variant"].as_str(), Some("not-pff"));
        assert_eq!(
            entry.metadata_json["email_parser_last_attempt_status"].as_str(),
            Some("not_pff")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_pst_mailbox_evidence_reports_corrupt_ansi_as_failed() -> Result<()> {
        let case_path = unique_case_path("pst-ansi-variant");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("pst-ansi-variant-source");
        let path = write_pst_fixture(&dir, "mail.pst", b"NOT-A-PST-FILE-AT-ALL")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: path.clone(),
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let prior = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(prior.len(), 1);
        assert_eq!(
            prior[0].metadata_json["email_parser_status"].as_str(),
            Some("not_pff")
        );

        let mut ansi_header = vec![0_u8; 12];
        ansi_header[0..4].copy_from_slice(b"!BDN");
        ansi_header[8..10].copy_from_slice(b"SM");
        ansi_header[10..12].copy_from_slice(&14_u16.to_le_bytes());
        fs::write(&path, &ansi_header)?;
        let error = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )
        .expect_err("corrupt ANSI PST must fail the processing job");
        assert!(format!("{error:#}").contains("ANSI PST open error"));
        let retained = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].id, prior[0].id);
        assert_eq!(
            retained[0].metadata_json["email_parser_status"].as_str(),
            Some("not_pff")
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_last_attempt_status"].as_str(),
            Some("failed")
        );
        assert_eq!(
            retained[0].metadata_json["pst_variant"].as_str(),
            Some("not-pff"),
            "failed reprocessing must not overwrite committed PFF provenance"
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_last_attempt_pst_variant"].as_str(),
            Some("ansi-classic-v14")
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_last_attempt_pst_header_version"].as_u64(),
            Some(14)
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_replacement_committed"].as_bool(),
            Some(false)
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_replacement_rolled_back"].as_bool(),
            Some(true)
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_previous_records_preserved"].as_bool(),
            Some(true)
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_retained_record_count"].as_i64(),
            Some(1)
        );
        assert!(retained[0].metadata_json["email_parser_last_attempt_error"]
            .as_str()
            .is_some_and(|message| message.contains("ANSI PST open error")));
        assert_eq!(
            list_evidence(&case_path)?[0].last_job_status.as_deref(),
            Some("failed")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_pst_mailbox_evidence_reports_unicode_parse_failure_gracefully() -> Result<()> {
        // A file that passes the cheap 12-byte Unicode-header sniff but is not a real,
        // structurally valid PST/OST container. The outlook-pst crate cannot open it, and
        // process_pst_mailbox_evidence must record a failed parser status with the exact
        // bounded diagnostic rather than crashing, hanging, or claiming unsupported/complete.
        let case_path = unique_case_path("pst-unicode-corrupt");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("pst-unicode-corrupt-source");
        let mut bytes = vec![0_u8; 4096];
        bytes[0..4].copy_from_slice(b"!BDN");
        bytes[8..10].copy_from_slice(b"SM");
        bytes[10..12].copy_from_slice(&23_u16.to_le_bytes());
        let path = write_pst_fixture(&dir, "mail.pst", &bytes)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let error = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )
        .expect_err("corrupt Unicode PST must fail the processing job");
        assert!(format!("{error:#}").contains("Unicode PST open error"));
        assert!(list_filesystem_entries(&case_path, Some(evidence_id))?.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_nst_mailbox_evidence_records_explicit_not_pff_status() -> Result<()> {
        let case_path = unique_case_path("nst-not-pff");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("nst-not-pff-source");
        let path = write_pst_fixture(&dir, "mail.nst", b"NOT-A-PFF-NST-FILE")?;

        let entry = pst_evidence_entry(&case_path, path)?;
        assert_eq!(entry.metadata_json["email_format"].as_str(), Some("nst"));
        assert_eq!(
            entry.metadata_json["email_parser_status"].as_str(),
            Some("not_pff")
        );
        assert_eq!(entry.metadata_json["pst_variant"].as_str(), Some("not-pff"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn process_pff_v36_records_recognized_unsupported_variant() -> Result<()> {
        let case_path = unique_case_path("pff-v36-unsupported");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("pff-v36-unsupported-source");
        let mut bytes = vec![0_u8; 32];
        bytes[0..4].copy_from_slice(b"!BDN");
        bytes[8..10].copy_from_slice(b"SO");
        bytes[10..12].copy_from_slice(&36_u16.to_le_bytes());
        let path = write_pst_fixture(&dir, "mail.ost", &bytes)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path,
                kind: EvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let first = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(first.entries_indexed, 1);
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.metadata_json["email_format"].as_str(), Some("ost"));
        assert_eq!(
            entry.metadata_json["email_parser_status"].as_str(),
            Some("unsupported_variant")
        );
        assert_eq!(
            entry.metadata_json["pst_variant"].as_str(),
            Some("unicode-4k-v36")
        );
        assert_eq!(
            entry.metadata_json["pst_page_size_bytes"].as_u64(),
            Some(4096)
        );
        assert_eq!(
            entry.metadata_json["pst_native_reader_supported"].as_bool(),
            Some(false)
        );

        let second = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(second.entries_indexed, 0);
        assert!(second.truncated);
        let retained = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].id, entry.id);
        assert_eq!(
            retained[0].metadata_json["email_parser_retained_record_count"].as_i64(),
            Some(1)
        );
        assert_eq!(
            retained[0].metadata_json["email_parser_previous_records_preserved"].as_bool(),
            Some(true)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn evidence_process_assigns_forensic_categories() -> Result<()> {
        let case_path = unique_case_path("evidence-categories");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("evidence-categories-source");
        fs::create_dir_all(evidence_dir.join("Pictures"))?;
        fs::write(evidence_dir.join("Pictures").join("photo.jpg"), b"jpg")?;
        fs::write(evidence_dir.join("mail.pst"), b"pst")?;
        fs::create_dir_all(
            evidence_dir
                .join("Users")
                .join("Examiner")
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default"),
        )?;
        fs::write(
            evidence_dir
                .join("Users")
                .join("Examiner")
                .join("AppData")
                .join("Local")
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Login Data"),
            b"sqlite",
        )?;
        fs::create_dir_all(evidence_dir.join("Windows").join("Prefetch"))?;
        fs::write(
            evidence_dir
                .join("Windows")
                .join("Prefetch")
                .join("APP.EXE-12345678.pf"),
            b"pf",
        )?;
        fs::create_dir_all(evidence_dir.join("OneDrive"))?;
        fs::write(evidence_dir.join("OneDrive").join("report.docx"), b"docx")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let category = |suffix: &str| -> (String, String) {
            let entry = entries
                .iter()
                .find(|entry| entry.logical_path.ends_with(suffix))
                .unwrap_or_else(|| panic!("missing categorized entry ending with {suffix}"));
            (
                entry.metadata_json["category_main"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                entry.metadata_json["category_sub"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        };
        assert_eq!(
            category("/Pictures/photo.jpg"),
            ("Pictures and Media".to_string(), "Pictures".to_string())
        );
        assert_eq!(
            category("/mail.pst"),
            (
                "Email and Communications".to_string(),
                "Email stores".to_string()
            )
        );
        assert_eq!(
            category("/Default/Login Data"),
            (
                "Accounts and Identity".to_string(),
                "Credential and secret stores".to_string()
            )
        );
        assert_eq!(
            category("/Windows/Prefetch/APP.EXE-12345678.pf"),
            (
                "Program Execution".to_string(),
                "Execution artifacts".to_string()
            )
        );
        assert_eq!(
            category("/OneDrive/report.docx"),
            ("Cloud and Web".to_string(), "Cloud sync".to_string())
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn classifier_precision_known_answers() {
        let metadata = serde_json::json!({});
        let classify =
            |logical_path: &str, name: &str| classify_entry(logical_path, name, "file", &metadata);

        let password_icon = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Windows/WinSxS/.../PasswordExpiry.contrast-black_scale-100.png",
            "PasswordExpiry.contrast-black_scale-100.png",
        );
        assert_eq!(
            (password_icon.main, password_icon.sub),
            ("Operating System", "System files")
        );
        assert_eq!(password_icon.confidence, "low");
        assert_ne!(password_icon.main, "Accounts and Identity");

        let credentials_dll = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Windows/WinSxS/.../Windows.Security.Credentials.UI.UserConsentVerifierManager.dll",
            "Windows.Security.Credentials.UI.UserConsentVerifierManager.dll",
        );
        assert_eq!(
            (credentials_dll.main, credentials_dll.sub),
            ("Operating System", "System files")
        );
        assert_eq!(credentials_dll.confidence, "low");
        assert_ne!(credentials_dll.main, "Accounts and Identity");

        let credentials_schema = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Windows/schemas/.../EapGenericUserCredentials.xsd",
            "EapGenericUserCredentials.xsd",
        );
        assert_eq!(
            (credentials_schema.main, credentials_schema.sub),
            ("Operating System", "System files")
        );
        assert_eq!(credentials_schema.confidence, "low");
        assert_ne!(credentials_schema.main, "Accounts and Identity");

        let chrome_login = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Users/john/AppData/Local/Google/Chrome/User Data/Default/Login Data",
            "Login Data",
        );
        assert_eq!(
            (chrome_login.main, chrome_login.sub),
            ("Accounts and Identity", "Credential and secret stores")
        );
        assert_eq!(chrome_login.confidence, "high");

        let firefox_key = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Users/john/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/key4.db",
            "key4.db",
        );
        assert_eq!(
            (firefox_key.main, firefox_key.sub),
            ("Accounts and Identity", "Credential and secret stores")
        );
        assert_eq!(firefox_key.confidence, "high");

        let sam = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Windows/System32/config/SAM",
            "SAM",
        );
        assert_eq!((sam.main, sam.sub), ("Operating System", "Registry hives"));
        assert_eq!(sam.confidence, "high");
        assert_ne!(sam.sub, "System files");

        let security_evtx = classify(
            "/Image Analysis/Volumes/003-Basic_data_partition/Windows/System32/winevt/Logs/Security.evtx",
            "Security.evtx",
        );
        assert_eq!(
            (security_evtx.main, security_evtx.sub),
            ("Operating System", "Event logs")
        );
        assert_eq!(security_evtx.confidence, "high");
    }

    #[test]
    fn classifier_type_gates_keywords_and_caps_fallback_confidence() {
        let metadata = serde_json::json!({});
        let password_icon = classify_entry(
            "/Users/john/Pictures/PasswordExpiry.png",
            "PasswordExpiry.png",
            "file",
            &metadata,
        );
        assert_eq!(
            (password_icon.main, password_icon.sub),
            ("Pictures and Media", "Pictures")
        );
        assert_eq!(password_icon.confidence, "medium");

        let password_notes = classify_entry(
            "/Users/john/Documents/password-notes.txt",
            "password-notes.txt",
            "file",
            &metadata,
        );
        assert_eq!(
            (password_notes.main, password_notes.sub),
            ("Documents and Office", "Text and notes")
        );
        assert_eq!(password_notes.confidence, "medium");

        let unrelated_startup_string = classify_entry(
            "/WindowsApps/Outlook/olk-startupShutdown.strings.json",
            "olk-startupShutdown.strings.json",
            "file",
            &metadata,
        );
        assert_ne!(
            (unrelated_startup_string.main, unrelated_startup_string.sub),
            ("Program Execution", "Startup and scheduled tasks")
        );

        let source_file = classify_entry(
            "/Users/john/projects/oauth_token.cs",
            "oauth_token.cs",
            "file",
            &metadata,
        );
        assert_eq!(
            (source_file.main, source_file.sub),
            ("Development and Source Code", "Source code")
        );
        assert_eq!(source_file.confidence, "medium");
    }

    #[test]
    fn timeline_date_range_matches_ntfs_and_fat_parser_timestamp_keys() -> Result<()> {
        // Regression for the dead date-range Timeline on real image cases:
        // image processing stores NTFS times under ntfs_*_time_utc and FAT
        // times under fat_*, but TIMELINE_TIME_FIELD_KEYS only listed the
        // generic/browser keys, so a range filter matched ~nothing.
        let case_path = unique_case_path("timeline-range-keys");
        create_test_case(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_sources(
                 case_id, source_kind, source_path, display_name, read_file_system_requested
             ) VALUES (?1, 'image', ?2, 'missing-image.raw', 1)",
            params![case_id, "Z:/does/not/exist/missing-image.raw"],
        )?;
        let evidence_id = conn.last_insert_rowid();
        let insert = |path: &str, name: &str, metadata: serde_json::Value| {
            conn.execute(
                "INSERT INTO filesystem_entries(
                     case_id, evidence_id, logical_path, name, entry_kind, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, 'file', ?5)",
                params![case_id, evidence_id, path, name, metadata.to_string()],
            )
        };
        insert(
            "/img/ntfs-in-range.txt",
            "ntfs-in-range.txt",
            serde_json::json!({
                "ntfs_modification_time_utc": "2022-08-16T22:03:58.000335800+00:00"
            }),
        )?;
        insert(
            "/img/fat-in-range.txt",
            "fat-in-range.txt",
            serde_json::json!({ "fat_modified": "2022-08-20T05:47:40Z" }),
        )?;
        insert(
            "/img/ntfs-out-of-range.txt",
            "ntfs-out-of-range.txt",
            serde_json::json!({
                "ntfs_modification_time_utc": "2023-01-01T00:00:00+00:00"
            }),
        )?;
        insert(
            "/img/fat-legacy-debug-format.txt",
            "fat-legacy-debug-format.txt",
            // Pre-fix rows carry Debug-formatted text; they must simply not
            // match (datetime() yields NULL), never error the whole query.
            serde_json::json!({
                "fat_modified": "DateTime { date: Date { year: 2022, month: 8, day: 16 }, time: Time { hour: 5, min: 47, sec: 40, millis: 0 } }"
            }),
        )?;
        // Tool bookkeeping rows (image container etc.) carry tool-side
        // timestamps like "when KDFT read the image"; they must NEVER appear
        // as timeline events, even when their timestamp falls in the range.
        insert(
            "/img/Container",
            "Container",
            serde_json::json!({
                "artifact_kind": "disk_image_container",
                "source_file_accessed_utc": "2022-08-16T12:00:00Z"
            }),
        )?;
        drop(conn);

        let range = Some(("2022-08-01T00:00:00Z", "2022-08-31T23:59:59Z"));
        let entries = list_filesystem_entries_for_timeline(&case_path, Some(100), range)?;
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, vec!["fat-in-range.txt", "ntfs-in-range.txt"]);
        assert_eq!(count_filesystem_entries_for_timeline(&case_path, range)?, 2);

        // Without a range every REAL entry is eligible, including legacy
        // rows; the container stays excluded.
        assert_eq!(
            list_filesystem_entries_for_timeline(&case_path, Some(100), None)?.len(),
            4
        );
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn metadata_only_processing_skips_content_and_email_reads() -> Result<()> {
        let case_path = unique_case_path("metadata-only-profile");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("metadata-only-source");
        fs::create_dir_all(&evidence_dir)?;
        fs::write(evidence_dir.join("note.txt"), b"searchable text body")?;
        fs::write(
            evidence_dir.join("message.eml"),
            b"From: alice@example.test\r\nTo: bob@example.test\r\nSubject: quarterly\r\n\r\nbody",
        )?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        // Metadata-only pass: no content capture, no email parsing.
        let result = process_evidence_with_profile(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
            ProcessingProfile {
                capture_content: false,
                parse_emails: false,
                parse_browsers: false,
            },
        )?;
        assert_eq!(result.status, "completed");
        {
            let conn = open_existing_case(&case_path)?;
            let with_content: i64 = conn.query_row(
                "SELECT COUNT(*) FROM filesystem_entries
                 WHERE evidence_id = ?1 AND content_head IS NOT NULL",
                params![evidence_id],
                |row| row.get(0),
            )?;
            assert_eq!(with_content, 0, "metadata-only index must read no content");
            let params_json: String = conn.query_row(
                "SELECT parameters_json FROM evidence_jobs
                 WHERE evidence_id = ?1 AND job_type = 'filesystem_index'
                 ORDER BY id DESC LIMIT 1",
                params![evidence_id],
                |row| row.get(0),
            )?;
            let params_json: serde_json::Value = serde_json::from_str(&params_json)?;
            assert_eq!(params_json["capture_content"].as_bool(), Some(false));
            assert_eq!(params_json["parse_emails"].as_bool(), Some(false));
        }
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let eml = entries
            .iter()
            .find(|entry| entry.name == "message.eml")
            .expect("eml indexed");
        assert!(
            eml.metadata_json.get("email_subject").is_none(),
            "email must not be parsed when disabled"
        );
        assert_eq!(
            eml.metadata_json["email_parser_status"].as_str(),
            Some("skipped")
        );
        assert_eq!(
            eml.metadata_json["email_parser_error"].as_str(),
            Some(EMAIL_PARSE_DISABLED_NOTE),
            "the .eml must disclose WHY it was not parsed: {:?}",
            eml.metadata_json
        );
        // Metadata itself is complete: names, kinds, sizes are all indexed.
        assert!(entries.iter().any(|entry| entry.name == "note.txt"
            && entry.size_bytes == Some("searchable text body".len() as i64)));
        // The evidence row tells the UI the index is metadata-only.
        let evidence_rows = list_evidence(&case_path)?;
        let row = evidence_rows
            .iter()
            .find(|row| row.id == evidence_id)
            .expect("evidence listed");
        assert_eq!(row.content_indexed, Some(false));

        // Re-process with the default profile: content and email come back.
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        {
            let conn = open_existing_case(&case_path)?;
            let with_content: i64 = conn.query_row(
                "SELECT COUNT(*) FROM filesystem_entries
                 WHERE evidence_id = ?1 AND content_head IS NOT NULL",
                params![evidence_id],
                |row| row.get(0),
            )?;
            assert!(with_content >= 1, "full profile must capture content");
        }
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let eml = entries
            .iter()
            .find(|entry| entry.name == "message.eml")
            .expect("eml indexed");
        assert_eq!(
            eml.metadata_json["email_subject"].as_str(),
            Some("quarterly")
        );
        let evidence_rows = list_evidence(&case_path)?;
        assert_eq!(
            evidence_rows
                .iter()
                .find(|row| row.id == evidence_id)
                .and_then(|row| row.content_indexed),
            Some(true)
        );
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&evidence_dir);
        Ok(())
    }

    #[test]
    fn create_bookmark_with_items_is_atomic() -> Result<()> {
        let case_path = unique_case_path("atomic-bookmark");
        create_test_case(&case_path)?;

        // A failing item (nonexistent entry id) must roll back EVERYTHING:
        // no folder, no bookmark, no audit rows from the aborted flow.
        let error = create_bookmark_with_items(
            &case_path,
            "Atomic Findings",
            CreateBookmarkOptions {
                folder_id: 0,
                bookmark_type: BookmarkType::NotableFile,
                data_type: Some("File".to_string()),
                title: Some("should roll back".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
            vec![CreateBookmarkItemOptions {
                bookmark_id: 0,
                evidence_id: None,
                entry_id: Some(987_654_321),
                item_order: None,
                display_name: None,
                logical_path: None,
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({}),
            }],
        );
        assert!(error.is_err(), "nonexistent entry id must fail the flow");
        assert!(
            list_bookmark_folders(&case_path)?.is_empty(),
            "rolled-back flow must not leave its folder"
        );
        assert!(list_bookmarks(&case_path)?.is_empty());
        {
            let conn = open_existing_case(&case_path)?;
            let orphan_audit: i64 = conn.query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE event_type IN ('bookmark.folder.create', 'bookmark.create')",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(orphan_audit, 0, "aborted flow must not leave audit rows");
        }

        // Happy path: folder + bookmark + item land together, and a second
        // bookmark reuses the same root folder instead of duplicating it.
        for round in 0..2 {
            let result = create_bookmark_with_items(
                &case_path,
                "Atomic Findings",
                CreateBookmarkOptions {
                    folder_id: 0,
                    bookmark_type: BookmarkType::HighlightedData,
                    data_type: Some("Search Hit".to_string()),
                    title: Some(format!("round {round}")),
                    examiner_comment: None,
                    in_report: true,
                    source_ref_json: serde_json::json!({}),
                    content_ref_json: serde_json::json!({}),
                },
                vec![CreateBookmarkItemOptions {
                    bookmark_id: 0,
                    evidence_id: None,
                    entry_id: None,
                    item_order: None,
                    display_name: Some(format!("hit {round}")),
                    logical_path: None,
                    selection_offset: Some(16),
                    selection_length: Some(4),
                    data_preview: None,
                    item_ref_json: serde_json::json!({}),
                }],
            )?;
            assert_eq!(result.items.len(), 1);
            assert_eq!(result.items[0].bookmark_id, result.bookmark_id);
        }
        let folders = list_bookmark_folders(&case_path)?;
        assert_eq!(
            folders
                .iter()
                .filter(|folder| folder.name == "Atomic Findings")
                .count(),
            1,
            "root folder must be reused, not duplicated"
        );
        assert_eq!(list_bookmarks(&case_path)?.len(), 2);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn remove_bookmark_folder_only_removes_empty_leaf_folders() -> Result<()> {
        let case_path = unique_case_path("remove-bookmark-folder");
        create_test_case(&case_path)?;

        // Empty leaf folder: removable, and the removal is audited by name.
        let empty_id = create_bookmark_folder(&case_path, None, "Accidental Empty", None, true)?;
        let removed = remove_bookmark_folder(&case_path, empty_id)?;
        assert_eq!(removed.folder_id, empty_id);
        assert_eq!(removed.name, "Accidental Empty");
        assert!(list_bookmark_folders(&case_path)?
            .iter()
            .all(|folder| folder.id != empty_id));
        {
            let conn = open_existing_case(&case_path)?;
            let details: String = conn.query_row(
                "SELECT details_json FROM audit_events
                 WHERE event_type = 'bookmark.folder.delete'
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )?;
            assert!(details.contains("Accidental Empty"));
        }

        // Folder holding a bookmark: refused.
        let used_id = create_bookmark_folder(&case_path, None, "Has Bookmark", None, true)?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: used_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: Some("File".to_string()),
                title: Some("keeps folder occupied".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        let error = remove_bookmark_folder(&case_path, used_id)
            .expect_err("folder with bookmarks must be refused");
        assert!(error.to_string().contains("bookmark(s)"), "{error}");

        // Folder with a child folder: refused.
        let parent_id = create_bookmark_folder(&case_path, None, "Parent", None, true)?;
        create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)?;
        let error = remove_bookmark_folder(&case_path, parent_id)
            .expect_err("folder with children must be refused");
        assert!(error.to_string().contains("child folder"), "{error}");

        // Unknown folder id: clean error.
        assert!(remove_bookmark_folder(&case_path, 987654).is_err());
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn normalize_legacy_fat_timestamp_known_answers() {
        // Legacy values stored using the previous Debug serialization.
        assert_eq!(
            normalize_legacy_fat_timestamp(
                "DateTime { date: Date { year: 2022, month: 8, day: 16 }, \
                 time: Time { hour: 14, min: 53, sec: 22, millis: 990 } }"
            )
            .as_deref(),
            Some("2022-08-16T14:53:22.990Z")
        );
        assert_eq!(
            normalize_legacy_fat_timestamp(
                "DateTime { date: Date { year: 2022, month: 8, day: 16 }, \
                 time: Time { hour: 5, min: 47, sec: 40, millis: 0 } }"
            )
            .as_deref(),
            Some("2022-08-16T05:47:40Z")
        );
        assert_eq!(
            normalize_legacy_fat_timestamp("Date { year: 2022, month: 8, day: 16 }").as_deref(),
            Some("2022-08-16")
        );
        // Zero/unset dates decode to no timestamp, matching fat_datetime_iso.
        assert_eq!(
            normalize_legacy_fat_timestamp(
                "DateTime { date: Date { year: 0, month: 0, day: 0 }, \
                 time: Time { hour: 0, min: 0, sec: 0, millis: 0 } }"
            ),
            None
        );
        // Already-normalized values must be left alone.
        assert_eq!(normalize_legacy_fat_timestamp("2022-08-16T05:47:40Z"), None);
        assert_eq!(normalize_legacy_fat_timestamp(""), None);
    }

    #[test]
    fn recategorize_repairs_legacy_fat_timestamps_into_timeline_range() -> Result<()> {
        let case_path = unique_case_path("fat-timestamp-repair");
        create_test_case(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_sources(
                 case_id, source_kind, source_path, display_name, read_file_system_requested
             ) VALUES (?1, 'image', ?2, 'missing-image.raw', 1)",
            params![case_id, "Z:/does/not/exist/missing-image.raw"],
        )?;
        let evidence_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, '/img/legacy-fat.txt', 'legacy-fat.txt', 'file', ?3)",
            params![
                case_id,
                evidence_id,
                serde_json::json!({
                    "filesystem_parser": "fatfs",
                    "fat_created": "DateTime { date: Date { year: 2022, month: 8, day: 16 }, time: Time { hour: 14, min: 53, sec: 22, millis: 990 } }",
                    "fat_accessed": "Date { year: 2022, month: 8, day: 16 }",
                    "fat_modified": "DateTime { date: Date { year: 2022, month: 8, day: 16 }, time: Time { hour: 5, min: 47, sec: 40, millis: 0 } }"
                })
                .to_string(),
            ],
        )?;
        drop(conn);

        // Before repair the legacy text is invisible to a date-range build.
        let range = Some(("2022-08-01T00:00:00Z", "2022-08-31T23:59:59Z"));
        assert_eq!(count_filesystem_entries_for_timeline(&case_path, range)?, 0);

        recategorize_case_entries(&case_path)?;

        let conn = open_existing_case(&case_path)?;
        let metadata: String = conn.query_row(
            "SELECT metadata_json FROM filesystem_entries WHERE case_id = ?1",
            params![case_id],
            |row| row.get(0),
        )?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
        assert_eq!(
            metadata["fat_created"].as_str(),
            Some("2022-08-16T14:53:22.990Z")
        );
        assert_eq!(metadata["fat_accessed"].as_str(), Some("2022-08-16"));
        assert_eq!(
            metadata["fat_modified"].as_str(),
            Some("2022-08-16T05:47:40Z")
        );
        assert_eq!(
            metadata["fat_time_basis"].as_str(),
            Some(FAT_TIME_BASIS_NOTE)
        );
        let audit: String = conn.query_row(
            "SELECT details_json FROM audit_events
             WHERE event_type = 'recategorize.run'
             ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        let audit: serde_json::Value = serde_json::from_str(&audit)?;
        assert_eq!(audit["fat_timestamps_repaired"].as_i64(), Some(1));
        drop(conn);

        // After repair the same entry is reachable by the Timeline range.
        assert_eq!(count_filesystem_entries_for_timeline(&case_path, range)?, 1);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn recategorize_case_entries_rewrites_stored_categories_without_evidence_read() -> Result<()> {
        let case_path = unique_case_path("recategorize");
        create_test_case(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_sources(
                 case_id, source_kind, source_path, display_name, read_file_system_requested
             ) VALUES (?1, 'image', ?2, 'missing-image.raw', 1)",
            params![case_id, "Z:/this/source/does/not/exist/missing-image.raw"],
        )?;
        let evidence_id = conn.last_insert_rowid();
        let wrong_system_category = serde_json::json!({
            "analysis_category": "Accounts and Identity / Credentials and tokens",
            "category_main": "Accounts and Identity",
            "category_sub": "Credentials and tokens",
            "category_source": "extension_path_rules_v1",
            "sentinel": "preserve-system-metadata"
        });
        let wrong_login_category = serde_json::json!({
            "analysis_category": "Documents and Office / Text and notes",
            "category_main": "Documents and Office",
            "category_sub": "Text and notes",
            "category_source": "extension_path_rules_v1",
            "sentinel": "preserve-login-metadata"
        });
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, 'file', ?5)",
            params![
                case_id,
                evidence_id,
                "/Image Analysis/Volumes/003-Basic_data_partition/Windows/WinSxS/PasswordExpiry.png",
                "PasswordExpiry.png",
                wrong_system_category.to_string(),
            ],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, 'file', ?5)",
            params![
                case_id,
                evidence_id,
                "/Image Analysis/Volumes/003-Basic_data_partition/Users/john/AppData/Local/Google/Chrome/User Data/Default/Login Data",
                "Login Data",
                wrong_login_category.to_string(),
            ],
        )?;
        drop(conn);

        assert_eq!(recategorize_case_entries(&case_path)?, 2);

        let conn = open_existing_case(&case_path)?;
        let mut stmt = conn.prepare(
            "SELECT name, metadata_json
             FROM filesystem_entries
             WHERE case_id = ?1
             ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![case_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let stored = rows
            .into_iter()
            .map(|(name, metadata)| {
                Ok((name, serde_json::from_str::<serde_json::Value>(&metadata)?))
            })
            .collect::<Result<Vec<_>>>()?;
        let system = &stored
            .iter()
            .find(|(name, _)| name == "PasswordExpiry.png")
            .expect("system entry remains stored")
            .1;
        assert_eq!(
            system["analysis_category"].as_str(),
            Some("Operating System / System files")
        );
        assert_eq!(system["category_confidence"].as_str(), Some("low"));
        assert_eq!(
            system["category_source"].as_str(),
            Some(ENTRY_CATEGORY_CLASSIFIER_VERSION)
        );
        assert_eq!(
            system["sentinel"].as_str(),
            Some("preserve-system-metadata")
        );
        let login = &stored
            .iter()
            .find(|(name, _)| name == "Login Data")
            .expect("login entry remains stored")
            .1;
        assert_eq!(
            login["analysis_category"].as_str(),
            Some("Accounts and Identity / Credential and secret stores")
        );
        assert_eq!(login["category_confidence"].as_str(), Some("high"));
        assert_eq!(
            login["category_source"].as_str(),
            Some(ENTRY_CATEGORY_CLASSIFIER_VERSION)
        );
        assert_eq!(login["sentinel"].as_str(), Some("preserve-login-metadata"));

        let audit_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'recategorize.run'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(audit_count, 1);
        let audit_details: String = conn.query_row(
            "SELECT details_json
             FROM audit_events
             WHERE event_type = 'recategorize.run'
             ORDER BY id DESC
             LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        let audit_details: serde_json::Value = serde_json::from_str(&audit_details)?;
        assert_eq!(audit_details["entries_updated"].as_i64(), Some(2));
        assert_eq!(
            audit_details["classifier_version"].as_str(),
            Some(ENTRY_CATEGORY_CLASSIFIER_VERSION)
        );
        let evidence_jobs: i64 =
            conn.query_row("SELECT COUNT(*) FROM evidence_jobs", [], |row| row.get(0))?;
        assert_eq!(evidence_jobs, 0);

        drop(stmt);
        drop(conn);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn os_paths_with_generic_artifact_words_do_not_classify_as_browser() -> Result<()> {
        let classify = |logical_path: &str, name: &str| {
            let mut metadata = serde_json::json!({});
            add_entry_category(&mut metadata, logical_path, name, "file");
            (
                metadata["category_main"].as_str().unwrap().to_string(),
                metadata["category_sub"].as_str().unwrap().to_string(),
            )
        };

        // System DLLs in dllcache must be classified as system files rather
        // than browser or credential artifacts.
        assert_eq!(
            classify(
                "/Volumes/001-part0/WINDOWS/system32/dllcache/acledit.dll",
                "acledit.dll"
            ),
            ("Operating System".to_string(), "System files".to_string())
        );
        assert_eq!(
            classify(
                "/Volumes/001-part0/WINDOWS/system32/dllcache/arp.exe",
                "arp.exe"
            ),
            ("Operating System".to_string(), "System files".to_string())
        );
        // Driver .img under Windows is not a disk image.
        let (img_main, _) = classify(
            "/Volumes/001-part0/WINDOWS/system32/drivers/netwlan5.img",
            "netwlan5.img",
        );
        assert_ne!(img_main, "Archives and Containers");
        assert_eq!(
            classify(
                "/Volumes/001-part0/Program Files/Tencent/QQ_Games/QQ_Bubble_Arena/map/desert01.img",
                "desert01.img"
            ),
            (
                "Pictures and Media".to_string(),
                "Graphics and design".to_string()
            )
        );

        // Real browser paths still classify as browser artifacts / cookies.
        assert_eq!(
            classify(
                "/Users/kris/AppData/Local/Google/Chrome/User Data/Default/Cache/f_000001",
                "f_000001"
            )
            .0,
            "Cloud and Web"
        );
        assert_eq!(
            classify(
                "/Users/kris/AppData/Local/Google/Chrome/User Data/Default/History",
                "History"
            ),
            ("Cloud and Web".to_string(), "Browser artifacts".to_string())
        );
        // Old-IE cookie path has no browser name: precision over recall means
        // it falls back to the .txt rule rather than guessing browser context.
        assert_eq!(
            classify(
                "/Documents and Settings/kris/Cookies/kris@ads[1].txt",
                "kris@ads[1].txt"
            ),
            (
                "Documents and Office".to_string(),
                "Text and notes".to_string()
            )
        );
        assert_eq!(
            classify(
                "/Users/kris/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite",
                "cookies.sqlite"
            )
            .0,
            "Accounts and Identity"
        );
        Ok(())
    }

    #[test]
    fn derived_records_use_artifact_semantics_instead_of_filename_extensions() -> Result<()> {
        let mut usn = serde_json::json!({
            "artifact_kind": "windows_usn_record",
            "source_entry_id": 321213,
        });
        add_entry_category(
            &mut usn,
            "/Windows Artifacts/321213/usn/00000000000000191576.record",
            "FTK Imager 8.2.0.iso",
            "record",
        );
        assert_eq!(usn["category_main"].as_str(), Some("User Activity"));
        assert_eq!(usn["category_sub"].as_str(), Some("NTFS change journal"));

        let mut diagnostic = serde_json::json!({
            "artifact_kind": "filesystem_parser_error",
        });
        add_entry_category(
            &mut diagnostic,
            "/Image Analysis/Volumes/000-whole-image/Parser Errors/Directory.record",
            "NTFS Directory Partial Parse",
            "record",
        );
        assert_eq!(diagnostic["category_hidden"].as_bool(), Some(true));
        assert_eq!(diagnostic["category_main"].as_str(), Some("Internal"));
        Ok(())
    }

    #[test]
    fn recovery_artifacts_get_distinct_categories() -> Result<()> {
        let mut deleted = serde_json::json!({ "artifact_kind": "deleted_file_record" });
        add_entry_category(
            &mut deleted,
            "/Recovery/Deleted Files/message.eml",
            "message.eml",
            "file",
        );
        assert_eq!(deleted["category_main"].as_str(), Some("Recovery"));
        assert_eq!(deleted["category_sub"].as_str(), Some("Deleted files"));

        let mut unallocated = serde_json::json!({ "artifact_kind": "unallocated_space" });
        add_entry_category(
            &mut unallocated,
            "/Recovery/Unallocated Space/chunk-1.bin",
            "chunk-1.bin",
            "file",
        );
        assert_eq!(unallocated["category_main"].as_str(), Some("Recovery"));
        assert_eq!(
            unallocated["category_sub"].as_str(),
            Some("Unallocated space")
        );
        Ok(())
    }

    #[test]
    fn required_invalid_eml_is_disclosed_and_truncates_processing() -> Result<()> {
        let case_path = unique_case_path("invalid-required-eml");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("invalid-required-eml-source");
        fs::write(
            evidence_dir.join("invalid.eml"),
            b"ordinary body text without any RFC 822 header\r\n",
        )?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let tracker =
            progress::JobProgressTracker::new("invalid-required-eml-test", "process", None);
        let result = progress::with_job_progress(&tracker, || {
            process_evidence(
                &case_path,
                ProcessEvidenceOptions {
                    evidence_id,
                    max_entries: 0,
                },
            )
        })?;
        assert!(result.truncated);
        assert_eq!(result.status, "truncated");
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.error_count, 1);
        assert_eq!(snapshot.skipped_count, 1);
        assert_eq!(snapshot.truncation_reason_count, 1);

        let entry = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .find(|entry| entry.name == "invalid.eml")
            .expect("invalid .eml remains indexed with parser disclosure");
        assert_eq!(
            entry.metadata_json["email_parser_status"].as_str(),
            Some("skipped")
        );
        assert_eq!(
            entry.metadata_json["email_parser_recognized"].as_bool(),
            Some(false)
        );
        assert_eq!(
            entry.metadata_json["email_parser_error_count"].as_u64(),
            Some(2)
        );
        assert_eq!(
            entry.metadata_json["email_parser_diagnostics"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert!(result
            .truncation_reasons
            .iter()
            .any(|reason| reason.contains("parser status skipped")));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn rfc822_stream_read_failure_has_exact_error_and_skip_status() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected read failure"))
            }
        }

        let mut metadata = serde_json::json!({});
        let result = annotate_email_metadata_from_reader(&mut metadata, "eml", FailingReader, true);
        assert_eq!(result.status, EmailAnnotationStatus::Failed);
        assert!(result.incomplete);
        assert_eq!(result.progress_error_count, 1);
        assert_eq!(result.progress_skip_count, 1);
        assert_eq!(result.parser_error_count, 1);
        assert_eq!(metadata["email_parser_status"].as_str(), Some("failed"));
        assert_eq!(metadata["email_parser_error_count"].as_u64(), Some(1));
        assert_eq!(
            metadata["email_parser_diagnostics"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            metadata["email_parser_diagnostics_omitted"].as_u64(),
            Some(0)
        );
    }

    #[test]
    fn successful_staged_parse_survives_cleanup_failure_with_warning() -> Result<()> {
        let outcome = combine_staged_parse_and_cleanup(
            Ok::<_, anyhow::Error>("parsed"),
            Err(anyhow!("injected cleanup denial")),
            "DOCX",
        )?;
        assert_eq!(outcome.parsed, "parsed");
        assert!(outcome
            .cleanup_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("injected cleanup denial")));

        let error = combine_staged_parse_and_cleanup::<()>(
            Err(anyhow!("primary parse failure")),
            Err(anyhow!("secondary cleanup failure")),
            "ZIP",
        )
        .expect_err("parse failure remains fatal");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("primary parse failure"));
        assert!(rendered.contains("secondary cleanup failure"));
        Ok(())
    }

    #[test]
    fn deleted_ntfs_diagnostic_samples_are_bounded_with_exact_counts() {
        let tracker =
            progress::JobProgressTracker::new("deleted-ntfs-diagnostics-test", "process", None);
        let diagnostics = progress::with_job_progress(&tracker, || {
            let mut diagnostics = NtfsDeletedScanDiagnostics::default();
            for record_number in 0..(NTFS_DELETED_SCAN_DIAGNOSTIC_LIMIT as u64 + 7) {
                diagnostics.record_error(
                    record_number,
                    "record_read",
                    "injected record error",
                    true,
                );
            }
            diagnostics
        });
        assert_eq!(
            diagnostics.diagnostic_count,
            NTFS_DELETED_SCAN_DIAGNOSTIC_LIMIT as u64 + 7
        );
        assert_eq!(
            diagnostics.record_read_error_count,
            diagnostics.diagnostic_count
        );
        assert_eq!(
            diagnostics.omitted_record_count,
            diagnostics.diagnostic_count
        );
        assert_eq!(
            diagnostics.samples.len(),
            NTFS_DELETED_SCAN_DIAGNOSTIC_LIMIT
        );
        assert_eq!(diagnostics.samples_omitted, 7);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.error_count, diagnostics.diagnostic_count);
        assert_eq!(snapshot.skipped_count, diagnostics.omitted_record_count);
    }

    #[test]
    fn evidence_process_parses_eml_and_report_formats_email_bookmark() -> Result<()> {
        let case_path = unique_case_path("email-parse-report");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("email-parse-source");
        let eml_path = evidence_dir.join("message.eml");
        let mut eml = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Quarterly plan\r\nDate: Tue, 30 Jun 2026 20:00:00 +0000\r\nMessage-ID: <plan@example.com>\r\n\r\nBob,\r\nThe mailbox evidence is ready for review.\r\n".to_vec();
        while eml.len() <= 1024 * 1024 + 4096 {
            eml.extend_from_slice(b"Additional complete body line for streaming validation.\r\n");
        }
        fs::write(&eml_path, &eml)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 10,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let message = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/message.eml"))
            .expect("message.eml should be indexed");
        assert_eq!(
            message.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );
        assert_eq!(
            message.metadata_json["category_sub"].as_str(),
            Some("Email messages")
        );
        assert_eq!(
            message.metadata_json["email_subject"].as_str(),
            Some("Quarterly plan")
        );
        assert_eq!(message.name, "message.eml");
        assert!(message.logical_path.ends_with("/message.eml"));
        assert_eq!(
            message.metadata_json["email_parser"].as_str(),
            Some("kdft-rfc822-stream-1")
        );
        assert_eq!(
            message.metadata_json["email_parser_status"].as_str(),
            Some("parsed")
        );
        assert_eq!(
            message.metadata_json["email_parser_bytes_consumed"].as_u64(),
            Some(eml.len() as u64)
        );
        assert_eq!(
            message.metadata_json["email_body_preview_truncated"].as_bool(),
            Some(true)
        );
        assert!(message.metadata_json["email_body_preview"]
            .as_str()
            .unwrap_or_default()
            .contains("mailbox evidence"));

        let folder_id = create_bookmark_folder(&case_path, None, "Emails", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Email,
                data_type: Some("Email Message".to_string()),
                title: Some("Email: Quarterly plan".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({ "entry_id": message.id }),
                content_ref_json: serde_json::json!({ "artifact_kind": "email_message" }),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(message.id),
                item_order: None,
                display_name: Some("Quarterly plan".to_string()),
                logical_path: Some(message.logical_path.clone()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("Alice to Bob".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "email_message",
                    "artifact_kind": "email_message",
                    "email_from": "Alice <alice@example.com>",
                    "email_to": "Bob <bob@example.com>",
                    "email_subject": "Quarterly plan",
                    "email_date": "Tue, 30 Jun 2026 20:00:00 +0000",
                    "email_body_preview": "Bob,\nThe mailbox evidence is ready for review.",
                    "logical_path": message.logical_path.clone(),
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("Email Message"));
        assert!(html.contains("Alice &lt;alice@example.com&gt;"));
        assert!(html.contains("Quarterly plan"));
        assert!(html.contains("mailbox evidence"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_parses_rfc822_txt_in_email_folder() -> Result<()> {
        let case_path = unique_case_path("email-txt-parse");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("email-txt-source");
        let email_dir = evidence_dir.join("Email");
        fs::create_dir_all(&email_dir)?;
        fs::write(
            email_dir.join("Charlie_2009-11-16_1102_Received.txt"),
            b"Subject:\r\nFound key\r\nFrom:\r\nFrank <frank@example.com>\r\nDate:\r\nMon, 16 Nov 2009 11:02:00 +0000\r\nTo:\r\nCharlie <charlie@example.com>\r\nMessage-ID:\r\n<found-key@example.com>\r\n\r\nCharlie,\r\nI found the key you asked about.\r\n",
        )?;
        fs::write(
            email_dir.join("readme.txt"),
            b"This is a plain note in the Email folder, not an RFC 822 message.\n",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 20,
            },
        )?;

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let message = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .ends_with("/Email/Charlie_2009-11-16_1102_Received.txt")
            })
            .expect("RFC 822 text email should be indexed");
        assert_eq!(
            message.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );
        assert_eq!(
            message.metadata_json["email_format"].as_str(),
            Some("text-rfc822")
        );
        assert_eq!(
            message.metadata_json["category_sub"].as_str(),
            Some("Email messages")
        );
        assert_eq!(
            message.metadata_json["email_subject"].as_str(),
            Some("Found key")
        );
        assert_eq!(
            message.metadata_json["email_from"].as_str(),
            Some("Frank <frank@example.com>")
        );
        assert_eq!(
            message.metadata_json["email_parser_status"].as_str(),
            Some("partial")
        );
        assert!(message.metadata_json["email_parser_diagnostics"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value
                .as_str()
                .is_some_and(|value| value.contains("Recovered an unindented value")))));

        let readme = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/Email/readme.txt"))
            .expect("plain text file should be indexed");
        assert_ne!(
            readme.metadata_json["artifact_kind"].as_str(),
            Some("email_message")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_evidence_auto_attaches_and_invalid_vdi_fails_loudly() -> Result<()> {
        let case_path = unique_case_path("vdi-source");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("vdi-source");
        let image_path = evidence_dir.join("disk.vdi");
        fs::write(&image_path, b"0123456789abcdef")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence[0].source_kind, "image");
        assert_eq!(filesystem_entry_count(&case_path)?, 0);
        assert!(list_filesystem_entries(&case_path, Some(evidence_id))?.is_empty());

        let err = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )
        .expect_err("invalid VDI image should fail loudly")
        .to_string();
        assert!(err.contains("decoding VDI image") || err.contains("Invalid VDI signature"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_analyzes_raw_mbr_partition_records() -> Result<()> {
        let case_path = unique_case_path("image-mbr");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-mbr-source");
        let image_path = evidence_dir.join("disk.img");
        create_test_mbr_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        assert_eq!(list_evidence(&case_path)?[0].source_kind, "image");

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(processed.entries_indexed >= 3);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Container.record"
                && entry.metadata_json["artifact_kind"].as_str() == Some("disk_image_container")
        }));
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Partitioning.report"
                && entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition_report")
                && entry.metadata_json["partition_scheme"].as_str() == Some("Mbr")
        }));
        let partition = entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition"))
            .expect("partition record should be created");
        assert_eq!(
            partition.metadata_json["start_offset"].as_u64(),
            Some(1_048_576)
        );
        assert_eq!(
            partition.metadata_json["size_bytes"].as_u64(),
            Some(1_048_576)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_hex_pattern_and_scoped_filters() -> Result<()> {
        let case_path = unique_case_path("deep-hex");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("deep-hex-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        // Byte-pattern mode: "FAT ev" = 46 41 54 20 65 76 at offset 0 of note.txt.
        let base = DeepSearchOptions {
            category: None,
            file_types: None,
            query: String::new(),
            evidence_id: None,
            include_content: true,
            max_results: 50,
            max_file_bytes: 65_536,
        };
        let hex_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "hex:46 41 54 20 65 76".to_string(),
                ..base.clone()
            },
        )?;
        let hit = hex_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/DFIR/note.txt"))
            .expect("hex pattern should hit note.txt content");
        assert_eq!(hit.match_kind, "content");
        assert_eq!(hit.selection_offset, Some(0));
        assert_eq!(hit.selection_length, Some(6));
        assert!(hit
            .data_preview
            .as_deref()
            .unwrap_or("")
            .starts_with("46 41 54"));

        // File-type scope: txt keeps the hit, jpg excludes it.
        let txt_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                file_types: Some(vec!["txt".to_string()]),
                ..base.clone()
            },
        )?;
        assert!(txt_hits
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let jpg_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                file_types: Some(vec!["jpg".to_string()]),
                ..base.clone()
            },
        )?;
        assert!(!jpg_hits
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));

        // Category scope: the entry's own stored main category and subcategory both match, while
        // a bogus one excludes.
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let note = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/DFIR/note.txt"))
            .expect("note.txt entry");
        let stored_category = note.metadata_json["category_main"]
            .as_str()
            .expect("stored category_main")
            .to_string();
        let scoped = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some(stored_category),
                ..base.clone()
            },
        )?;
        assert!(scoped
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let stored_subcategory = note.metadata_json["category_sub"]
            .as_str()
            .expect("stored category_sub")
            .to_string();
        let subcategory_scoped = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some(stored_subcategory),
                ..base.clone()
            },
        )?;
        assert!(subcategory_scoped
            .iter()
            .any(|hit| hit.logical_path.ends_with("/DFIR/note.txt")));
        let excluded = deep_search(
            &case_path,
            DeepSearchOptions {
                query: "artifact".to_string(),
                category: Some("no-such-category".to_string()),
                ..base
            },
        )?;
        assert!(excluded.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn raw_search_location_helpers_classify_partitions_gaps_and_file_evidence() {
        let volumes = vec![
            LiveVolume {
                index: 0,
                volume_index_zero_based: 0,
                partition_number_one_based: Some(1),
                name: "001-system".to_string(),
                filesystem: "FAT".to_string(),
                start_offset: 1024,
                size_bytes: 2048,
                browsable: true,
                bitlocker: None,
            },
            LiveVolume {
                index: 1,
                volume_index_zero_based: 1,
                partition_number_one_based: Some(2),
                name: "002-data".to_string(),
                filesystem: "NTFS".to_string(),
                start_offset: 8192,
                size_bytes: 4096,
                browsable: true,
                bitlocker: None,
            },
        ];

        assert_eq!(raw_search_sector(1536, RAW_SEARCH_SECTOR_SIZE), 3);

        let in_partition = classify_raw_hit_location("image", 2048, &volumes);
        assert_eq!(in_partition.partition_index, Some(0));
        assert_eq!(in_partition.volume_index_zero_based, Some(0));
        assert_eq!(in_partition.partition_number_one_based, Some(1));
        assert_eq!(in_partition.volume_name.as_deref(), Some("001-system"));
        assert_eq!(in_partition.partition_start_offset, Some(1024));
        assert_eq!(in_partition.filesystem.as_deref(), Some("FAT"));
        assert_eq!(in_partition.region, "in-partition");

        let gap = classify_raw_hit_location("image", 4096, &volumes);
        assert_eq!(gap.partition_index, None);
        assert_eq!(gap.volume_index_zero_based, None);
        assert_eq!(gap.partition_number_one_based, None);
        assert_eq!(gap.volume_name, None);
        assert_eq!(gap.region, "partition-gap/unpartitioned");

        let file = classify_raw_hit_location("file", 2048, &volumes);
        assert_eq!(file.partition_index, None);
        assert_eq!(file.region, "not-applicable (file evidence)");
    }

    #[test]
    fn raw_disk_search_records_audit_and_returns_provenance() -> Result<()> {
        let case_path = unique_case_path("raw-search-audit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("raw-search-audit-source");
        let evidence_path = evidence_dir.join("bytes.bin");
        fs::write(
            &evidence_path,
            b"prefix needle suffix with enough trailing bytes",
        )?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path.clone(),
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let hash = hash_evidence(&case_path, evidence_id)?;

        let result = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: "needle".to_string(),
                max_results: 5,
                max_scan_bytes: 64,
            },
        )?;

        assert_eq!(result.evidence_id, evidence_id);
        assert_eq!(result.evidence_display_name, "bytes.bin");
        assert_eq!(result.source_path, stable_path_string(&evidence_path));
        assert_eq!(
            result.evidence_sha256_hex.as_deref(),
            Some(hash.sha256_hex.as_str())
        );
        assert_eq!(
            result.evidence_hashed_at.as_deref(),
            Some(hash.hashed_at.as_str())
        );
        assert_eq!(result.sector_size, 512);
        assert_eq!(result.actor, "Test Examiner");
        assert_eq!(result.query, "needle");
        assert_eq!(
            result.encodings,
            vec![
                "ascii".to_string(),
                "utf16le".to_string(),
                "utf16be".to_string()
            ]
        );
        assert_eq!(result.scan_start, 0);
        assert_eq!(result.max_scan_bytes, 64);
        assert_eq!(result.max_results, 5);
        assert_eq!(result.hits.len(), 1);
        assert!(result.searched_at.ends_with('Z'));
        assert_eq!(result.hits[0].offset, 7);
        assert_eq!(result.hits[0].sector, 0);
        assert_eq!(result.hits[0].region, "not-applicable (file evidence)");
        assert_eq!(
            result.coverage.source_scope,
            "attached file byte stream from offset zero through EOF (or an explicitly reported examiner byte budget)"
        );
        assert!(!result.coverage.folder_evidence_supported);
        assert!(result.hits[0].data_preview.contains("6E 65 65 64 6C 65"));
        assert!(result.hits[0].ascii_preview.contains("needle"));

        let conn = open_existing_case(&case_path)?;
        let (actor, object_id, details_json): (String, i64, String) = conn.query_row(
            "SELECT actor, object_id, details_json
             FROM audit_events
             WHERE event_type = 'raw_search.run'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(actor, "Test Examiner");
        assert_eq!(object_id, evidence_id);
        let details: serde_json::Value = serde_json::from_str(&details_json)?;
        assert_eq!(details["query"], "needle");
        assert_eq!(details["encodings"][0], "ascii");
        assert_eq!(details["bytes_scanned"], result.bytes_scanned);
        assert_eq!(details["total_size"], result.total_size);
        assert_eq!(details["hit_count"], 1);
        assert_eq!(details["truncated"], false);
        assert_eq!(details["max_scan_bytes"], 64);
        assert_eq!(details["sector_size"], 512);
        assert_eq!(details["evidence_sha256_hex"], hash.sha256_hex);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn raw_disk_search_finds_ascii_hits_starting_in_retained_overlap() -> Result<()> {
        let case_path = unique_case_path("raw-search-boundary");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("raw-search-boundary-source");
        let evidence_path = evidence_dir.join("bytes.bin");
        let needle = b"KDFT_BOUNDARY_MARK";
        let needle_len = needle.len();
        let max_needle_len = needle_len * 2;
        let overlap = max_needle_len - 1;
        let first_window_safe_len = RAW_SEARCH_CHUNK_BYTES - overlap;
        let old_miss_zone_start = first_window_safe_len - needle_len + 1;
        let old_miss_zone_end = first_window_safe_len - 1;
        let retained_overlap_offset = old_miss_zone_start + 5;
        assert!(
            retained_overlap_offset >= old_miss_zone_start
                && retained_overlap_offset <= old_miss_zone_end,
            "test offset must stay inside old miss zone"
        );

        let boundary_offset = RAW_SEARCH_CHUNK_BYTES - 7;
        assert!(boundary_offset < RAW_SEARCH_CHUNK_BYTES);
        assert!(boundary_offset + needle_len > RAW_SEARCH_CHUNK_BYTES);
        let control_offset = 1000_usize;

        let mut evidence = fs::File::create(&evidence_path)?;
        evidence.set_len((RAW_SEARCH_CHUNK_BYTES + 4096) as u64)?;
        for offset in [retained_overlap_offset, boundary_offset, control_offset] {
            evidence.seek(SeekFrom::Start(offset as u64))?;
            evidence.write_all(needle)?;
        }
        drop(evidence);

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path.clone(),
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let result = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: String::from_utf8_lossy(needle).into_owned(),
                max_results: 20,
                max_scan_bytes: 0,
            },
        )?;

        let ascii_offsets = result
            .hits
            .iter()
            .filter(|hit| hit.encoding == "ascii")
            .map(|hit| hit.offset)
            .collect::<Vec<_>>();
        let expected_offsets = [
            retained_overlap_offset as u64,
            boundary_offset as u64,
            control_offset as u64,
        ];
        assert_eq!(
            ascii_offsets.len(),
            expected_offsets.len(),
            "unexpected ascii hits: {ascii_offsets:?}"
        );
        for expected in expected_offsets {
            assert_eq!(
                ascii_offsets
                    .iter()
                    .filter(|actual| **actual == expected)
                    .count(),
                1,
                "missing or duplicate ascii hit at {expected}; got {ascii_offsets:?}"
            );
        }

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn indexed_directory_root_collapses_synthetic_image_containers() -> Result<()> {
        let case_path = unique_case_path("idx-collapse");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("idx-collapse-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let root = list_indexed_directory(&case_path, evidence_id, "/", 1000)?;
        assert!(
            !root
                .children
                .iter()
                .any(|child| child.name == "Image Analysis"),
            "root listing must not expose the synthetic Image Analysis container"
        );
        let volume = root
            .children
            .iter()
            .find(|child| child.logical_path == "/Image Analysis/Volumes/001-part0")
            .expect("volume folder should surface at the device root");
        assert!(volume.is_dir);
        assert!(
            !root.children.iter().any(|child| {
                child.logical_path == "/Image Analysis/Container.record" && !child.is_dir
            }),
            "parser-produced record rows must not appear in the read-only Entries tree"
        );
        let compact_entries =
            list_evidence_tree_entries_limited(&case_path, Some(evidence_id), None)?;
        assert!(compact_entries
            .iter()
            .all(|entry| entry.entry_kind != "record"));
        assert_eq!(
            evidence_tree_entry_count(&case_path)?,
            i64::try_from(compact_entries.len()).unwrap()
        );
        let volume_children = list_indexed_directory(
            &case_path,
            evidence_id,
            "/Image Analysis/Volumes/001-part0",
            1000,
        )?;
        assert!(volume_children
            .children
            .iter()
            .any(|child| child.name == "DFIR" && child.is_dir));

        // Report directory trees collapse the same synthetic containers.
        let report = report_data_with_directory_structure(&case_path, 1000)?;
        let tree = report
            .directory_trees
            .iter()
            .find(|tree| tree.evidence_id == evidence_id)
            .expect("image evidence should have a report tree");
        assert!(
            !tree
                .lines
                .iter()
                .any(|line| line.name == "Image Analysis" || line.name == "Volumes"),
            "report tree must not contain synthetic containers"
        );
        let volume_line = tree
            .lines
            .iter()
            .find(|line| line.name == "001-part0")
            .expect("volume folder should be a report tree root");
        assert_eq!(volume_line.depth, 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn indexed_directory_pages_every_direct_child_without_subtree_scan_cap() -> Result<()> {
        let case_path = unique_case_path("idx-pagination");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("idx-pagination-source");
        fs::write(evidence_dir.join("seed.txt"), b"seed")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let mut conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for index in 0..1005 {
            let name = format!("item-{index:04}.txt");
            let path = format!("/paged/{name}");
            upsert_filesystem_entry(
                &tx,
                case_id,
                evidence_id,
                &path,
                &name,
                "file",
                Some(0),
                "{}",
                processed.job_id,
            )?;
            let root_name = format!("root-{index:04}.txt");
            upsert_filesystem_entry(
                &tx,
                case_id,
                evidence_id,
                &format!("/{root_name}"),
                &root_name,
                "file",
                Some(0),
                "{}",
                processed.job_id,
            )?;
        }
        // A folder evidence source may legitimately contain this name. It
        // must remain a normal paged directory rather than triggering the
        // image-only synthetic-container hoisting rule.
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            "/Image Analysis/user.txt",
            "user.txt",
            "file",
            Some(0),
            "{}",
            processed.job_id,
        )?;
        tx.commit()?;

        let first = list_indexed_directory_page(&case_path, evidence_id, "/paged", 0, 1000)?;
        assert_eq!(first.offset, 0);
        assert_eq!(first.children.len(), 1000);
        assert_eq!(first.total_children, 1005);
        assert_eq!(first.next_offset, Some(1000));
        assert!(first.truncated);

        let second = list_indexed_directory_page(&case_path, evidence_id, "/paged", 1000, 1000)?;
        assert_eq!(second.offset, 1000);
        assert_eq!(second.children.len(), 5);
        assert_eq!(second.total_children, 1005);
        assert_eq!(second.next_offset, None);
        assert!(!second.truncated);
        let all_paths = first
            .children
            .iter()
            .chain(second.children.iter())
            .map(|child| child.logical_path.clone())
            .collect::<HashSet<_>>();
        assert_eq!(all_paths.len(), 1005);

        let root_first = list_indexed_directory_page(&case_path, evidence_id, "/", 0, 1000)?;
        let root_second = list_indexed_directory_page(&case_path, evidence_id, "/", 1000, 1000)?;
        assert_eq!(root_first.total_children, 1008);
        assert_eq!(root_first.next_offset, Some(1000));
        assert_eq!(root_second.children.len(), 8);
        assert_eq!(root_second.next_offset, None);
        assert!(root_first
            .children
            .iter()
            .any(|child| { child.logical_path == "/Image Analysis" && child.is_dir }));
        let root_paths = root_first
            .children
            .iter()
            .chain(root_second.children.iter())
            .map(|child| child.logical_path.clone())
            .collect::<HashSet<_>>();
        assert_eq!(root_paths.len(), 1008);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_fat_partition_entries() -> Result<()> {
        let case_path = unique_case_path("image-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-fat-source");
        let image_path = evidence_dir.join("fat-disk.img");
        create_test_fat_mbr_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let live_volumes = list_image_volumes(&image_path)?;
        assert_eq!(live_volumes.len(), 1);
        assert_eq!(live_volumes[0].index, 0);
        assert_eq!(live_volumes[0].volume_index_zero_based, 0);
        assert_eq!(live_volumes[0].partition_number_one_based, Some(1));

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/001-part0"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("fatfs")
        }));
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR"
                && entry.entry_kind == "directory"
        }));
        let note = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt")
            .expect("FAT file should be indexed");
        assert_eq!(note.entry_kind, "file");
        assert_eq!(note.size_bytes, Some(21));
        assert_eq!(
            note.metadata_json["volume_index_zero_based"].as_u64(),
            Some(0)
        );
        assert_eq!(
            note.metadata_json["partition_number_one_based"].as_u64(),
            Some(1)
        );
        assert_eq!(
            note.metadata_json["source_entry_name"].as_str(),
            Some("note.txt")
        );
        // Indexed FAT timestamps must be ISO-8601 text (sortable, range-
        // filterable), never Debug-formatted struct dumps, and must carry the
        // local-time basis note.
        for key in ["fat_created", "fat_modified"] {
            let value = note.metadata_json[key]
                .as_str()
                .unwrap_or_else(|| panic!("{key} should be stored as a string"));
            assert!(
                value.len() >= 20 && value[4..5] == *"-" && value[10..11] == *"T",
                "{key} should be ISO-8601, got {value}"
            );
            assert!(!value.contains('{'), "{key} still Debug-formatted: {value}");
        }
        assert_eq!(
            note.metadata_json["fat_time_basis"].as_str(),
            Some(FAT_TIME_BASIS_NOTE)
        );
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");
        assert_eq!(bytes.total_size, 21);
        let spaced = entries
            .iter()
            .find(|entry| entry.source_path_exact.as_deref() == Some("Case Files/note (1).txt"))
            .expect("FAT file with an exact spaced source path should be indexed");
        assert_eq!(
            spaced.metadata_json["fat_path"].as_str(),
            Some("Case Files/note (1).txt")
        );
        assert_eq!(
            spaced.metadata_json["source_path_exact"].as_str(),
            Some("Case Files/note (1).txt")
        );
        assert_eq!(
            spaced.metadata_json["internal_path_key"].as_str(),
            Some(spaced.internal_path_key.as_str())
        );
        assert_ne!(
            spaced.internal_path_key,
            "/Image Analysis/Volumes/001-part0/Case Files/note (1).txt"
        );
        assert_eq!(
            spaced.metadata_json["partition_size_bytes"].as_u64(),
            Some(1_048_576)
        );
        let spaced_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: spaced.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(spaced_bytes.bytes, b"FAT spaced artifact");

        // EA-005 known-answer collision corpus: these are two distinct source
        // files with independently known bytes. The old sanitizer mapped both
        // names to Nitroba_work.odt and silently upserted one over the other.
        let nitroba_entries = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.source_path_exact.as_deref(),
                    Some("Nitroba work.odt" | "Nitroba_work.odt")
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(nitroba_entries.len(), 2);
        assert_ne!(
            nitroba_entries[0].internal_path_key,
            nitroba_entries[1].internal_path_key
        );
        let exact_spaced = nitroba_entries
            .iter()
            .copied()
            .find(|entry| entry.source_path_exact.as_deref() == Some("Nitroba work.odt"))
            .expect("spaced Nitroba oracle");
        let exact_underscore = nitroba_entries
            .iter()
            .copied()
            .find(|entry| entry.source_path_exact.as_deref() == Some("Nitroba_work.odt"))
            .expect("underscore Nitroba oracle");
        let exact_spaced_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: exact_spaced.id,
                offset: 0,
                length: 64,
            },
        )?;
        let exact_underscore_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: exact_underscore.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(exact_spaced_bytes.bytes, b"known spaced ODT payload");
        assert_eq!(
            exact_underscore_bytes.bytes,
            b"known underscore ODT payload"
        );

        let nitroba_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "Nitroba".to_string(),
                evidence_id: Some(evidence_id),
                include_content: false,
                max_results: 10,
                max_file_bytes: 64,
            },
        )?;
        assert_eq!(nitroba_hits.len(), 2);
        assert!(nitroba_hits.iter().any(|hit| {
            hit.source_path_exact.as_deref() == Some("Nitroba work.odt")
                && hit.internal_path_key == hit.logical_path
        }));
        assert!(nitroba_hits
            .iter()
            .any(|hit| hit.source_path_exact.as_deref() == Some("Nitroba_work.odt")));

        let raw_result = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: "known spaced ODT payload".to_string(),
                max_results: 10,
                max_scan_bytes: 0,
            },
        )?;
        assert_eq!(raw_result.hits.len(), 1);
        assert_eq!(raw_result.hits[0].partition_index, Some(0));
        assert_eq!(raw_result.hits[0].volume_index_zero_based, Some(0));
        assert_eq!(raw_result.hits[0].partition_number_one_based, Some(1));
        record_live_export(
            &case_path,
            evidence_id,
            0,
            "Nitroba work.odt",
            &LiveExportResult {
                output_path: "known-answer-output.odt".to_string(),
                bytes_written: 24,
                total_size: 24,
                sha256_hex: "test-only-known-answer".to_string(),
            },
        )?;
        let conn = open_existing_case(&case_path)?;
        let export_audit: String = conn.query_row(
            "SELECT details_json FROM audit_events
             WHERE event_type = 'live.export' AND object_id = ?1
             ORDER BY id DESC LIMIT 1",
            params![evidence_id],
            |row| row.get(0),
        )?;
        drop(conn);
        let export_audit: serde_json::Value = serde_json::from_str(&export_audit)?;
        assert_eq!(export_audit["volume_index_zero_based"], 0);
        assert_eq!(export_audit["partition_number_one_based"], 1);

        let internal_paths_before = nitroba_entries
            .iter()
            .map(|entry| {
                (
                    entry.source_path_exact.clone().unwrap_or_default(),
                    entry.internal_path_key.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let bookmark_id = create_test_bookmark(&case_path)?;
        let bookmarked = add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(exact_spaced.id),
                item_order: None,
                display_name: None,
                logical_path: None,
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({}),
            },
        )?;
        assert_eq!(
            bookmarked.item_ref_json["source_path_exact"].as_str(),
            Some("Nitroba work.odt")
        );
        assert_eq!(
            bookmarked.item_ref_json["internal_path_key"].as_str(),
            Some(exact_spaced.internal_path_key.as_str())
        );
        assert_eq!(
            bookmarked.item_ref_json["volume_index_zero_based"].as_u64(),
            Some(0)
        );
        assert_eq!(
            bookmarked.item_ref_json["partition_number_one_based"].as_u64(),
            Some(1)
        );
        let conn = open_existing_case(&case_path)?;
        let bookmark_audit: String = conn.query_row(
            "SELECT details_json FROM audit_events
             WHERE event_type = 'bookmark.item.add' AND object_id = ?1",
            params![bookmarked.id],
            |row| row.get(0),
        )?;
        drop(conn);
        let bookmark_audit: serde_json::Value = serde_json::from_str(&bookmark_audit)?;
        assert_eq!(bookmark_audit["volume_index_zero_based"], 0);
        assert_eq!(bookmark_audit["partition_number_one_based"], 1);

        // Reprocessing must reproduce navigation keys exactly; the report must
        // continue to present the immutable source path, not that key.
        let reprocessed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(reprocessed.status, "completed");
        let reprocessed_entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let internal_paths_after = reprocessed_entries
            .iter()
            .filter_map(|entry| {
                entry.source_path_exact.as_ref().and_then(|exact| {
                    exact
                        .starts_with("Nitroba")
                        .then(|| (exact.clone(), entry.internal_path_key.clone()))
                })
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(internal_paths_after, internal_paths_before);
        let tree_report = report_data_with_directory_structure(&case_path, 100)?;
        assert!(tree_report.directory_trees[0]
            .lines
            .iter()
            .any(|line| line.name == "Case Files"));
        assert!(!tree_report.directory_trees[0]
            .lines
            .iter()
            .any(|line| line.name.starts_with("Case_Files")));
        let report_html = render_report_html(&report_data(&case_path)?);
        assert!(report_html.contains("Exact source path:</strong> Nitroba work.odt"));
        assert!(report_html.contains("<dt>Source Path (exact)</dt><dd>Nitroba work.odt</dd>"));
        assert!(report_html.contains("KDFT internal path:"));
        assert!(report_html.contains("<dt>Volume Index (zero-based)</dt><dd>0</dd>"));
        assert!(report_html.contains("<dt>Partition Number (one-based)</dt><dd>1</dd>"));
        assert!(!report_html.contains("<dt>Partition Index</dt>"));

        let content_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "FAT evidence artifact".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64,
            },
        )?;
        let content_hit = content_hits
            .iter()
            .find(|hit| {
                hit.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt"
                    && hit.match_kind == "content"
            })
            .expect("Deep Search should scan image-backed FAT file content");
        assert_eq!(content_hit.selection_offset, Some(0));
        assert_eq!(
            content_hit.selection_length,
            Some("FAT evidence artifact".len() as i64)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_raw_read_serves_decoded_device_offsets() -> Result<()> {
        let case_path = unique_case_path("image-raw-read");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-raw-read-source");
        let image_path = evidence_dir.join("test.dd");
        let image = test_fat_mbr_image_bytes()?;
        fs::write(&image_path, &image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let (mbr, total_size) = read_image_raw_bytes(&case_path, evidence_id, 0, 512)?;
        assert_eq!(total_size, image.len() as u64);
        assert_eq!(mbr, image[..512]);

        let volumes = list_image_volumes(&image_path)?;
        let start = volumes
            .first()
            .expect("FAT fixture should expose a volume")
            .start_offset;
        let (volume_head, total_size_again) =
            read_image_raw_bytes(&case_path, evidence_id, start, 64)?;
        assert_eq!(total_size_again, image.len() as u64);
        assert_eq!(
            volume_head,
            image[start as usize..start as usize + 64].to_vec()
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_raw_find_is_bounded_and_matches_text_utf16le_and_hex() -> Result<()> {
        let case_path = unique_case_path("image-raw-find");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-raw-find-source");
        let image_path = evidence_dir.join("find.dd");
        let mut image = vec![0_u8; 160];
        image[13..19].copy_from_slice(b"Needle");
        let utf16_offset = 53;
        for (index, unit) in "UnicodeNeedle".encode_utf16().enumerate() {
            image[utf16_offset + (index * 2)..utf16_offset + (index * 2) + 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
        image[31..35].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        image[120..129].copy_from_slice(b"late-text");
        fs::write(&image_path, &image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let text_hit = find_in_image_raw_with_limits(
            &case_path,
            evidence_id,
            0,
            "needle",
            RawFindKind::Text,
            16,
            80,
        )?;
        assert_eq!(text_hit.match_offset, Some(13));
        assert_eq!(text_hit.match_length, Some(6));

        let utf16_hit = find_in_image_raw_with_limits(
            &case_path,
            evidence_id,
            20,
            "unicodeneedle",
            RawFindKind::Text,
            16,
            80,
        )?;
        assert_eq!(utf16_hit.match_offset, Some(utf16_offset as u64));
        assert_eq!(utf16_hit.match_length, Some("UnicodeNeedle".len() * 2));

        let hex_hit = find_in_image_raw_with_limits(
            &case_path,
            evidence_id,
            0,
            "DE AD BE EF",
            RawFindKind::Hex,
            32,
            80,
        )?;
        assert_eq!(hex_hit.match_offset, Some(31));
        assert_eq!(hex_hit.match_length, Some(4));

        let first_window = find_in_image_raw_with_limits(
            &case_path,
            evidence_id,
            0,
            "late-text",
            RawFindKind::Text,
            16,
            64,
        )?;
        assert_eq!(first_window.match_offset, None);
        assert_eq!(first_window.scanned_to, 64);
        assert!(!first_window.eof);
        assert!(first_window.next_scan_offset < first_window.scanned_to);
        assert!(first_window.next_scan_offset > 0);

        let continued = find_in_image_raw_with_limits(
            &case_path,
            evidence_id,
            first_window.next_scan_offset,
            "late-text",
            RawFindKind::Text,
            16,
            128,
        )?;
        assert_eq!(continued.match_offset, Some(120));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    /// Builds a minimal, spec-correct ext4 image (block size 1024, one block
    /// group, extent-mapped inodes) containing /hello.txt and an inline
    /// /hello-link symlink, for exercising the ext parser without an external
    /// fixture or mke2fs. Regular-file inodes use the
    /// extent tree format (not classic ext2 direct block pointers) because
    /// real ext4 filesystems - and this crate's directory/file readers -
    /// require the EXTENTS inode flag; mke2fs.ext4 sets it on every inode by
    /// default, so this matches genuine evidence rather than legacy ext2.
    fn build_minimal_ext2_image(payload: &[u8]) -> Vec<u8> {
        const BS: usize = 1024;
        const EXTENTS_FLAG: u32 = 0x0008_0000;
        let mut img = vec![0_u8; 64 * BS];
        let put_u32 = |img: &mut [u8], off: usize, value: u32| {
            img[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        let put_u16 = |img: &mut [u8], off: usize, value: u16| {
            img[off..off + 2].copy_from_slice(&value.to_le_bytes());
        };
        // Writes a single-entry, depth-0 extent tree into an inode's 60-byte
        // i_block area (offset 40 within the inode), mapping logical block 0
        // to physical `data_block` for `len` blocks.
        let put_extent_header = |img: &mut [u8], inode_off: usize, data_block: u32, len: u16| {
            let block = inode_off + 40;
            img[block] = 0x0A; // eh_magic low byte
            img[block + 1] = 0xF3; // eh_magic high byte
            put_u16(img, block + 2, 1); // eh_entries
            put_u16(img, block + 4, 4); // eh_max
            put_u16(img, block + 6, 0); // eh_depth (0 = leaf, extents follow inline)
            put_u32(img, block + 8, 0); // eh_generation
            put_u32(img, block + 12, 0); // ee_block (logical block 0)
            put_u16(img, block + 16, len); // ee_len
            put_u16(img, block + 18, 0); // ee_start_hi
            put_u32(img, block + 20, data_block); // ee_start_lo
        };

        // Superblock (block 1).
        let sb = BS;
        put_u32(&mut img, sb, 16); // s_inodes_count
        put_u32(&mut img, sb + 4, 64); // s_blocks_count
        put_u32(&mut img, sb + 20, 1); // s_first_data_block
        put_u32(&mut img, sb + 24, 0); // s_log_block_size -> 1024
        put_u32(&mut img, sb + 28, 0); // s_log_frag_size
        put_u32(&mut img, sb + 32, 64); // s_blocks_per_group
        put_u32(&mut img, sb + 36, 64); // s_frags_per_group
        put_u32(&mut img, sb + 40, 16); // s_inodes_per_group
        put_u16(&mut img, sb + 56, 0xEF53); // s_magic (0x38)
        put_u16(&mut img, sb + 58, 1); // s_state
        put_u16(&mut img, sb + 60, 1); // s_errors
        put_u32(&mut img, sb + 76, 1); // s_rev_level = dynamic
        put_u32(&mut img, sb + 84, 11); // s_first_ino
        put_u16(&mut img, sb + 88, 128); // s_inode_size
        put_u32(&mut img, sb + 96, 0x42); // s_feature_incompat = FILETYPE | EXTENTS

        // Block group descriptor (block 2).
        let gd = 2 * BS;
        put_u32(&mut img, gd, 3); // bg_block_bitmap
        put_u32(&mut img, gd + 4, 4); // bg_inode_bitmap
        put_u32(&mut img, gd + 8, 5); // bg_inode_table

        // Inode table (blocks 5-6), 128-byte inodes.
        let root = 5 * BS + 128; // inode 2
        put_u16(&mut img, root, 0x41ED); // dir, 0755
        put_u32(&mut img, root + 4, 1024); // i_size
        put_u16(&mut img, root + 26, 3); // i_links_count
        put_u32(&mut img, root + 28, 2); // i_blocks (512-byte units)
        put_u32(&mut img, root + 32, EXTENTS_FLAG); // i_flags
        put_extent_header(&mut img, root, 7, 1); // i_block -> extent tree: block 7

        let hello = 5 * BS + 10 * 128; // inode 11
        put_u16(&mut img, hello, 0x81A4); // reg, 0644
        put_u32(&mut img, hello + 4, payload.len() as u32); // i_size
        put_u16(&mut img, hello + 26, 1); // i_links_count
        put_u32(&mut img, hello + 28, 2); // i_blocks
        put_u32(&mut img, hello + 32, EXTENTS_FLAG); // i_flags
        put_extent_header(&mut img, hello, 8, 1); // i_block -> extent tree: block 8

        let hello_link = 5 * BS + 11 * 128; // inode 12
        put_u16(&mut img, hello_link, 0xA1FF); // symlink, 0777
        put_u32(&mut img, hello_link + 4, 9); // i_size: "hello.txt"
        put_u16(&mut img, hello_link + 26, 1); // i_links_count
        put_u32(&mut img, hello_link + 28, 0); // inline target consumes no data blocks
        img[hello_link + 40..hello_link + 49].copy_from_slice(b"hello.txt");

        // Root directory data (block 7).
        let dir = 7 * BS;
        put_u32(&mut img, dir, 2); // "." -> inode 2
        put_u16(&mut img, dir + 4, 12);
        img[dir + 6] = 1;
        img[dir + 7] = 2;
        img[dir + 8] = b'.';
        put_u32(&mut img, dir + 12, 2); // ".." -> inode 2
        put_u16(&mut img, dir + 16, 12);
        img[dir + 18] = 2;
        img[dir + 19] = 2;
        img[dir + 20] = b'.';
        img[dir + 21] = b'.';
        put_u32(&mut img, dir + 24, 11); // "hello.txt" -> inode 11
        put_u16(&mut img, dir + 28, 20);
        img[dir + 30] = 9;
        img[dir + 31] = 1;
        img[dir + 32..dir + 41].copy_from_slice(b"hello.txt");
        put_u32(&mut img, dir + 44, 12); // "hello-link" -> inode 12
        put_u16(&mut img, dir + 48, 980); // rec_len fills the block
        img[dir + 50] = 10;
        img[dir + 51] = 7; // EXT4_FT_SYMLINK
        img[dir + 52..dir + 62].copy_from_slice(b"hello-link");

        // File data (block 8).
        img[8 * BS..8 * BS + payload.len()].copy_from_slice(payload);
        img
    }

    /// Builds a raw image carrying a btrfs primary superblock (magic + a few
    /// metadata fields) at the standard 64 KiB offset.
    fn build_btrfs_superblock_image(label: &str, total_bytes: u64) -> Vec<u8> {
        let mut img = vec![0_u8; 128 * 1024];
        let sb = 0x1_0000;
        img[sb + 0x40..sb + 0x48].copy_from_slice(b"_BHRfS_M");
        for (i, byte) in (0..16).zip(0xA0_u8..) {
            img[sb + 0x20 + i] = byte;
        }
        img[sb + 0x70..sb + 0x78].copy_from_slice(&total_bytes.to_le_bytes());
        img[sb + 0x78..sb + 0x80].copy_from_slice(&(total_bytes / 4).to_le_bytes());
        img[sb + 0x88..sb + 0x90].copy_from_slice(&1_u64.to_le_bytes()); // num_devices
        img[sb + 0x90..sb + 0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sector size
        img[sb + 0x94..sb + 0x98].copy_from_slice(&16384_u32.to_le_bytes()); // node size
        let label_bytes = label.as_bytes();
        img[sb + 0x12B..sb + 0x12B + label_bytes.len()].copy_from_slice(label_bytes);
        img
    }

    #[test]
    fn live_browse_lists_directories_without_indexing() -> Result<()> {
        let dir = unique_temp_dir("live-browse");

        // FAT volume inside an MBR partition: /DFIR/note.txt.
        let fat_image = dir.join("fat.img");
        fs::write(&fat_image, test_fat_mbr_image_bytes()?)?;
        let volumes = list_image_volumes(&fat_image)?;
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].filesystem, "FAT");
        assert!(volumes[0].browsable);

        let root = list_image_directory(&fat_image, 0, "/")?;
        assert!(root
            .iter()
            .any(|entry| entry.name == "DFIR" && entry.is_dir));
        let dfir = list_image_directory(&fat_image, 0, "DFIR")?;
        let note = dfir
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case("note.txt"))
            .expect("note.txt listed live");
        assert!(!note.is_dir);
        let (bytes, total) = read_image_directory_bytes(&fat_image, 0, "DFIR/note.txt", 0, 64)?;
        assert_eq!(bytes, b"FAT evidence artifact");
        assert_eq!(total, b"FAT evidence artifact".len() as u64);

        // ext2 whole-image volume: /hello.txt.
        let ext_image = dir.join("ext.img");
        let payload = b"ext live payload";
        fs::write(&ext_image, build_minimal_ext2_image(payload))?;
        let ext_volumes = list_image_volumes(&ext_image)?;
        assert_eq!(ext_volumes.len(), 1);
        assert_eq!(ext_volumes[0].filesystem, "EXT");
        let ext_root = list_image_directory(&ext_image, 0, "/")?;
        assert!(ext_root.iter().any(|entry| entry.name == "hello.txt"));
        let (ext_bytes, ext_total) = read_image_directory_bytes(&ext_image, 0, "hello.txt", 0, 64)?;
        assert_eq!(ext_bytes, payload);
        assert_eq!(ext_total, payload.len() as u64);

        // No case database is touched by live browsing.
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn local_live_directory_pages_are_sorted_complete_and_non_overlapping() -> Result<()> {
        let case_path = unique_case_path("local-live-list");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-list-source");
        let sorted_dir = evidence_dir.join("sorted");
        fs::create_dir_all(sorted_dir.join("zeta"))?;
        fs::create_dir_all(sorted_dir.join("alpha"))?;
        fs::write(sorted_dir.join("b.txt"), b"b")?;
        fs::write(sorted_dir.join("A.txt"), b"a")?;
        let many_dir = evidence_dir.join("many");
        fs::create_dir_all(&many_dir)?;
        for index in 0..1005 {
            fs::write(many_dir.join(format!("file-{index:05}.txt")), b"x")?;
        }

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let sorted = list_local_directory(&case_path, evidence_id, "/sorted")?;
        assert!(!sorted.truncated);
        let names = sorted
            .entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.is_dir))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("alpha", true),
                ("zeta", true),
                ("A.txt", false),
                ("b.txt", false)
            ]
        );

        let first = list_local_directory_page(&case_path, evidence_id, "/many", None, 1000)?;
        assert_eq!(first.entries.len(), 1000);
        assert_eq!(first.total_entries, 1005);
        assert!(first.truncated);
        assert!(first.next_cursor.is_some());
        assert!(first.entries.windows(2).all(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            local_entry_sort(left, right) != std::cmp::Ordering::Greater
        }));
        let second = list_local_directory_page(
            &case_path,
            evidence_id,
            "/many",
            first.next_cursor.as_ref(),
            1000,
        )?;
        assert_eq!(second.entries.len(), 5);
        assert_eq!(second.total_entries, 1005);
        assert!(!second.truncated);
        assert!(second.next_cursor.is_none());
        let names = first
            .entries
            .iter()
            .chain(second.entries.iter())
            .map(|entry| entry.name.clone())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), 1005);

        let all = list_local_directory(&case_path, evidence_id, "/many")?;
        assert_eq!(all.entries.len(), 1005);
        assert!(!all.truncated);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn local_live_reads_byte_window() -> Result<()> {
        let case_path = unique_case_path("local-live-bytes");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-bytes-source");
        fs::write(evidence_dir.join("bytes.bin"), b"0123456789abcdef")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let (bytes, total) =
            read_local_evidence_bytes(&case_path, evidence_id, "/bytes.bin", 4, 6)?;
        assert_eq!(bytes, b"456789");
        assert_eq!(total, 16);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn local_live_single_file_lists_and_reads_attached_file() -> Result<()> {
        let case_path = unique_case_path("local-live-single-file");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-single-file-source");
        let file_path = evidence_dir.join("one.txt");
        fs::write(&file_path, b"single-file evidence")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: file_path.clone(),
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let listing = list_local_directory(&case_path, evidence_id, "/")?;
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "one.txt");
        assert!(!listing.entries[0].is_dir);
        let (bytes, total) = read_local_evidence_bytes(&case_path, evidence_id, "/one.txt", 7, 4)?;
        assert_eq!(bytes, b"file");
        assert_eq!(total, b"single-file evidence".len() as u64);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn local_live_exports_file_byte_exact_with_sha256() -> Result<()> {
        let case_path = unique_case_path("local-live-export");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-export-source");
        let payload = b"export me exactly";
        fs::write(evidence_dir.join("payload.bin"), payload)?;
        let output_dir = unique_temp_dir("local-live-export-output");
        let output_path = output_dir.join("payload.bin");
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let result = export_local_file(&case_path, evidence_id, "/payload.bin", &output_path)?;
        assert_eq!(fs::read(&output_path)?, payload);
        assert_eq!(result.bytes_written, payload.len() as u64);
        let mut hasher = Sha256::new();
        hasher.update(payload);
        assert_eq!(result.sha256_hex, format!("{:x}", hasher.finalize()));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(output_dir);
        Ok(())
    }

    #[test]
    fn local_live_exports_tree_with_manifest() -> Result<()> {
        let case_path = unique_case_path("local-live-tree");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-tree-source");
        fs::create_dir_all(evidence_dir.join("dir"))?;
        fs::write(evidence_dir.join("root.txt"), b"root")?;
        fs::write(evidence_dir.join("dir").join("nested.txt"), b"nested")?;
        let output_dir = unique_temp_dir("local-live-tree-output");
        fs::write(output_dir.join("kdft-manifest.csv"), b"examiner-owned")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let result = export_local_tree(&case_path, evidence_id, "/", &output_dir, None)?;
        assert_eq!(result.files_exported, 2);
        assert_eq!(result.directories_visited, 2);
        assert_eq!(result.file_limit, None);
        assert!(!result.file_limit_reached);
        assert!(!result.truncated);
        assert_eq!(result.skipped_count, 0);
        assert_eq!(fs::read(output_dir.join("root.txt"))?, b"root");
        assert_eq!(
            fs::read(output_dir.join("dir").join("nested.txt"))?,
            b"nested"
        );
        assert_eq!(
            fs::read(output_dir.join("kdft-manifest.csv"))?,
            b"examiner-owned"
        );
        assert_eq!(
            Path::new(&result.manifest_path).file_name(),
            Some(std::ffi::OsStr::new("kdft-manifest-2.csv"))
        );
        let manifest = fs::read_to_string(&result.manifest_path)?;
        assert!(manifest.starts_with("relative_path,size,sha256\r\n"));
        assert!(manifest.contains("\"root.txt\",4,"));
        assert!(
            manifest.contains("\"dir\\nested.txt\",6,")
                || manifest.contains("\"dir/nested.txt\",6,")
        );
        record_live_tree_export_with_source_kind(
            &case_path,
            evidence_id,
            "folder",
            0,
            "/",
            &result,
        )?;

        let limited_output = unique_temp_dir("local-live-tree-limited-output");
        let limited = export_local_tree(&case_path, evidence_id, "/", &limited_output, Some(1))?;
        assert_eq!(limited.files_exported, 1);
        assert_eq!(limited.file_limit, Some(1));
        assert!(limited.file_limit_reached);
        assert!(limited.truncated);

        let zero_output = unique_temp_dir("local-live-tree-zero-output");
        let zero_unlimited =
            export_local_tree(&case_path, evidence_id, "/", &zero_output, Some(0))?;
        assert_eq!(zero_unlimited.files_exported, 2);
        assert_eq!(zero_unlimited.file_limit, None);
        assert!(!zero_unlimited.file_limit_reached);
        assert!(!zero_unlimited.truncated);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(output_dir);
        let _ = fs::remove_dir_all(limited_output);
        let _ = fs::remove_dir_all(zero_output);
        Ok(())
    }

    #[test]
    fn live_tree_unlimited_semantics_exceed_former_hidden_caps() {
        assert_eq!(normalize_optional_file_limit(None), None);
        assert_eq!(normalize_optional_file_limit(Some(0)), None);
        assert!(file_limit_allows(10_001, None));
        assert!(file_limit_allows(
            10_001,
            normalize_optional_file_limit(Some(0))
        ));
        assert!(file_limit_allows(10_001, Some(20_000)));
        assert!(!file_limit_allows(10_000, Some(10_000)));

        let mut export = TreeExportSink::new(Path::new("unused-live-tree-output"), None);
        export.files = 10_001;
        export.dirs = 5_001;
        assert!(export.file_budget_left());
        assert!(!export.file_limit_reached);

        let mut listing = TreeListSink::new(0);
        for index in 0..10_001 {
            listing.push(&[format!("canonical-{index}.bin")], index, None, None, None);
        }
        listing.dirs = 5_001;
        assert!(listing.file_budget_left());
        assert!(!listing.file_limit_reached);

        let mut explicitly_limited = TreeListSink::new(10_000);
        explicitly_limited.files = listing.files;
        assert!(!explicitly_limited.file_budget_left());
        explicitly_limited.mark_file_limit_reached();
        let explicitly_limited = explicitly_limited.finish();
        assert_eq!(explicitly_limited.file_limit, Some(10_000));
        assert!(explicitly_limited.file_limit_reached);
        assert!(explicitly_limited.truncated);

        let mut oversized = TreeExportSink::new(Path::new("unused-live-tree-output"), None);
        oversized.skip_oversized("/large.bin", LIVE_EXPORT_MAX_BYTES + 1);
        assert_eq!(oversized.oversized_files_skipped, 1);
        assert_eq!(oversized.skipped_count, 1);
        assert!(oversized.truncated);
        assert!(oversized.skipped[0].contains(&LIVE_EXPORT_MAX_BYTES.to_string()));

        for index in 0..(LIVE_TREE_EXPORT_MAX_SKIP_NOTES + 25) {
            oversized.skip(format!("skipped-{index}"));
        }
        assert_eq!(oversized.skipped.len(), LIVE_TREE_EXPORT_MAX_SKIP_NOTES);
        assert_eq!(
            oversized.skipped_count,
            (LIVE_TREE_EXPORT_MAX_SKIP_NOTES + 26) as u64
        );

        let allowed_depth = vec!["d".to_string(); LIVE_TREE_MAX_PATH_DEPTH];
        let excessive_depth = vec!["d".to_string(); LIVE_TREE_MAX_PATH_DEPTH + 1];
        assert!(live_tree_depth_allowed(&allowed_depth));
        assert!(!live_tree_depth_allowed(&excessive_depth));
    }

    #[test]
    fn tree_export_rejects_linked_output_subdirectories() -> Result<()> {
        let output_root = unique_temp_dir("tree-export-link-root");
        let outside = unique_temp_dir("tree-export-link-outside");
        let linked = output_root.join("linked");

        #[cfg(windows)]
        let link_result = std::os::windows::fs::symlink_dir(&outside, &linked);
        #[cfg(unix)]
        let link_result = std::os::unix::fs::symlink(&outside, &linked);
        #[cfg(not(any(windows, unix)))]
        let link_result: io::Result<()> = Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory links are unavailable on this platform",
        ));

        if link_result.is_err() {
            let _ = fs::remove_dir_all(output_root);
            let _ = fs::remove_dir_all(outside);
            return Ok(());
        }

        let mut sink = TreeExportSink::new(&output_root, None);
        sink.prepare_output_root()?;
        let error = sink
            .unique_output_path(&["linked".to_string(), "escaped.bin".to_string()])
            .unwrap_err();
        assert!(error.to_string().contains("real directory"));
        assert!(!outside.join("escaped.bin").exists());

        #[cfg(windows)]
        fs::remove_dir(&linked)?;
        #[cfg(unix)]
        fs::remove_file(&linked)?;
        fs::remove_dir_all(output_root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn local_live_rejects_parent_directory_traversal() -> Result<()> {
        let case_path = unique_case_path("local-live-traversal");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-traversal-source");
        fs::write(evidence_dir.join("inside.txt"), b"inside")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let err = list_local_directory(&case_path, evidence_id, "../")
            .expect_err("parent traversal should be rejected")
            .to_string();
        assert!(err.contains("..") || err.contains("escapes evidence root"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn local_live_rejects_symlink_escape() -> Result<()> {
        let case_path = unique_case_path("local-live-symlink-escape");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("local-live-symlink-escape-source");
        let outside_dir = unique_temp_dir("local-live-symlink-outside");
        let outside_file = outside_dir.join("outside.txt");
        fs::write(&outside_file, b"outside")?;
        std::os::unix::fs::symlink(&outside_file, evidence_dir.join("escape.txt"))?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let err = read_local_evidence_bytes(&case_path, evidence_id, "/escape.txt", 0, 16)
            .expect_err("symlink escape should be rejected")
            .to_string();
        assert!(err.contains("symlink") || err.contains("escapes evidence root"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(outside_dir);
        Ok(())
    }

    #[test]
    fn image_process_records_btrfs_volume_metadata() -> Result<()> {
        let case_path = unique_case_path("image-btrfs");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-btrfs-source");
        let image_path = evidence_dir.join("btrfs.img");
        fs::write(
            &image_path,
            build_btrfs_superblock_image("EVIDENCE-VOL", 128 * 1024),
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let volume = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["filesystem_parser"].as_str() == Some("btrfs-metadata")
            })
            .expect("btrfs volume record should be indexed");
        assert_eq!(volume.metadata_json["filesystem"].as_str(), Some("btrfs"));
        assert_eq!(
            volume.metadata_json["btrfs_label"].as_str(),
            Some("EVIDENCE-VOL")
        );
        assert_eq!(
            volume.metadata_json["btrfs_sector_size"].as_u64(),
            Some(4096)
        );
        assert_eq!(
            volume.metadata_json["btrfs_node_size"].as_u64(),
            Some(16384)
        );
        assert!(volume.metadata_json["btrfs_fsid"]
            .as_str()
            .is_some_and(|fsid| fsid.len() == 32));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn detect_volume_filesystem_recognizes_ext_magic() -> Result<()> {
        let image = build_minimal_ext2_image(b"x");
        let mut cursor = io::Cursor::new(image);
        assert_eq!(detect_volume_filesystem_at(&mut cursor, 0)?, Some("EXT"));
        Ok(())
    }

    #[test]
    fn overflowing_ext_candidate_geometry_is_rejected_without_error() -> Result<()> {
        let mut image = vec![0_u8; 4096];
        image[0x438..0x43A].copy_from_slice(&0xEF53_u16.to_le_bytes());
        image[0x418..0x41C].copy_from_slice(&6_u32.to_le_bytes());
        image[0x404..0x408].copy_from_slice(&u32::MAX.to_le_bytes());
        image[0x460..0x464].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x550..0x554].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut cursor = io::Cursor::new(image);
        assert_eq!(recovered_ext_volume_size(&mut cursor, 0)?, None);
        Ok(())
    }

    #[test]
    fn ext_partial_parser_error_does_not_become_a_walk_stop() {
        let mut traversal = ExtTraversalState::default();
        traversal.record_partial_error();
        assert!(traversal.is_truncated());
        assert!(
            !traversal.should_stop(),
            "a disclosed parser error must not omit unrelated later directories"
        );

        traversal.record_limit_stop();
        assert!(traversal.should_stop());
    }

    #[test]
    fn image_process_indexes_ext_volume() -> Result<()> {
        let case_path = unique_case_path("image-ext");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-ext-source");
        let image_path = evidence_dir.join("ext.img");
        let payload = b"ext4 evidence payload";
        fs::write(&image_path, build_minimal_ext2_image(payload))?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("ext4")
        }));
        let hello = entries
            .iter()
            .find(|entry| entry.name == "hello.txt")
            .expect("ext file hello.txt should be indexed");
        assert_eq!(hello.size_bytes, Some(payload.len() as i64));
        assert_eq!(hello.metadata_json["ext_path"].as_str(), Some("/hello.txt"));

        // The file's bytes are readable through the ext byte reader.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: hello.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, payload);
        assert!(bytes.eof);

        // File view is reconstructed and file-relative, while the disk
        // location identifies the same leading bytes in the decoded image.
        let location = filesystem_entry_disk_location(&case_path, hello.id)?;
        assert!(location.available && location.exact_start);
        assert_eq!(location.file_relative_offset, Some(0));
        assert_eq!(location.contiguous_bytes, Some(payload.len() as u64));
        assert_eq!(location.decoded_media_offset, Some(8 * 1024));
        let image = fs::read(&image_path)?;
        let physical_start = location.decoded_media_offset.expect("physical offset") as usize;
        assert_eq!(
            &image[physical_start..physical_start + payload.len()],
            payload
        );

        // A short ext symlink stores its literal target inside i_block. The
        // logical file view must not prepend a synthetic display label, and
        // the file-system view must point to those exact inline bytes.
        let hello_link = entries
            .iter()
            .find(|entry| entry.name == "hello-link")
            .expect("inline ext symlink should be indexed");
        assert_eq!(hello_link.size_bytes, Some(9));
        assert_eq!(
            hello_link.metadata_json["ext_is_symlink"].as_bool(),
            Some(true)
        );
        let link_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: hello_link.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(link_bytes.total_size, 9);
        assert_eq!(link_bytes.bytes, b"hello.txt");
        let link_location = filesystem_entry_disk_location(&case_path, hello_link.id)?;
        assert_eq!(
            link_location.basis,
            "ext inline symlink target in inode record"
        );
        assert_eq!(link_location.file_relative_offset, Some(0));
        assert_eq!(link_location.contiguous_bytes, Some(9));
        let link_physical = link_location
            .decoded_media_offset
            .expect("inline symlink physical offset") as usize;
        assert_eq!(&image[link_physical..link_physical + 9], b"hello.txt");
        assert_eq!(
            hello_link.metadata_json["ext_inode_physical_offset"].as_u64(),
            Some((link_physical - 40) as u64)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn carve_evidence_recovers_files_by_signature() -> Result<()> {
        let case_path = unique_case_path("carve-evidence");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("carve-evidence-source");
        let image_path = dir.join("carve.img");

        // A raw image with a complete JPEG and PNG embedded at unaligned
        // offsets in otherwise-zeroed space (no filesystem).
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg.extend_from_slice(b"JFIF payload bytes here");
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(b"IHDR...pixels...");
        png.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);

        let mut image = vec![0_u8; 512 * 1024];
        let jpeg_offset = 4096 + 17;
        let png_offset = 200_000;
        // A GZIP header with no footer rule: its length cannot be measured,
        // so the carve must say so instead of presenting the fallback bound
        // as a real file size.
        let gzip_offset = 400_000;
        image[jpeg_offset..jpeg_offset + jpeg.len()].copy_from_slice(&jpeg);
        image[png_offset..png_offset + png.len()].copy_from_slice(&png);
        image[gzip_offset..gzip_offset + 3].copy_from_slice(&[0x1F, 0x8B, 0x08]);
        fs::write(&image_path, &image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        // Attach-only; carving is examiner-driven and independent of indexing.
        let result = carve_evidence(
            &case_path,
            evidence_id,
            CarveOptions {
                max_scan_bytes: 0,
                max_files: 0,
            },
        )?;
        assert_eq!(result.carved_files, 3);
        assert!(!result.truncated);
        assert_eq!(result.status, "completed");
        assert!(result.truncation_reasons.is_empty());
        assert_eq!(result.protective_extent_limit_hits, 0);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let carved: Vec<_> = entries
            .iter()
            .filter(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("carved_file"))
            .collect();
        assert_eq!(carved.len(), 3);

        let jpg = carved
            .iter()
            .find(|entry| entry.name.ends_with(".jpg"))
            .expect("carved JPEG present");
        assert_eq!(
            jpg.metadata_json["file_data_physical_offset"].as_u64(),
            Some(jpeg_offset as u64)
        );
        assert_eq!(jpg.size_bytes, Some(jpeg.len() as i64));
        assert_eq!(
            jpg.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            jpg.metadata_json["category_sub"].as_str(),
            Some("Carved files")
        );
        // Footer-measured length: the entry says so, with no caveat.
        assert_eq!(
            jpg.metadata_json["carve_length_basis"].as_str(),
            Some("format footer signature located by streaming search")
        );
        assert_eq!(
            jpg.metadata_json["carve_length_definitive"].as_bool(),
            Some(true)
        );
        assert_eq!(
            jpg.metadata_json["recovery_status"].as_str(),
            Some("carved from image by file signature")
        );

        // Footerless format: the recorded size is only a bound and every
        // examiner-facing field must say the end was never verified.
        let gz = carved
            .iter()
            .find(|entry| entry.name.ends_with(".gz"))
            .expect("carved GZIP present");
        assert_eq!(
            gz.metadata_json["file_data_physical_offset"].as_u64(),
            Some(gzip_offset as u64)
        );
        assert_eq!(gz.size_bytes, Some((image.len() - gzip_offset) as i64));
        assert_eq!(
            gz.metadata_json["carve_length_basis"].as_str(),
            Some("no supported end rule before end of available scan scope; end not verified")
        );
        assert_eq!(
            gz.metadata_json["carve_length_definitive"].as_bool(),
            Some(false)
        );
        assert!(gz.metadata_json["recovery_status"]
            .as_str()
            .unwrap_or_default()
            .contains("length not verified"));

        // Carved bytes are recoverable exactly via the physical-extent reader.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: jpg.id,
                offset: 0,
                length: 1024,
            },
        )?;
        assert_eq!(bytes.bytes, jpeg);
        assert!(bytes.eof);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn footer_aware_carve_length_streams_beyond_unknown_format_limit() -> Result<()> {
        let signature = CARVE_SIGNATURES
            .iter()
            .find(|signature| signature.extension == "jpg")
            .expect("JPEG carve signature");
        let mut bytes = vec![0_u8; CARVE_LENGTH_CHUNK_BYTES + 16];
        bytes[..signature.header.len()].copy_from_slice(signature.header);
        let footer_offset = CARVE_LENGTH_CHUNK_BYTES - 1;
        bytes[footer_offset..footer_offset + 2].copy_from_slice(&[0xFF, 0xD9]);
        let available_len = bytes.len() as u64;
        let mut reader = std::io::Cursor::new(bytes);

        let length =
            carve_length_with_protective_limit(&mut reader, 0, signature, available_len, 32)?;

        assert_eq!(length.length, (footer_offset + 2) as u64);
        assert!(length.definitive);
        assert!(!length.protective_limit_hit);
        assert_eq!(
            length.basis,
            "format footer signature located by streaming search"
        );
        Ok(())
    }

    #[test]
    fn unknown_length_carve_limit_truncates_result_job_and_entry() -> Result<()> {
        let case_path = unique_case_path("carve-protective-limit");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("carve-protective-limit-source");
        let image_path = dir.join("carve-limit.img");
        let mut image = vec![0_u8; 512];
        let zip_offset = 37_usize;
        image[zip_offset..zip_offset + 4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        let jpeg_offset = 200_usize;
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, b'x', 0xFF, 0xD9];
        image[jpeg_offset..jpeg_offset + jpeg.len()].copy_from_slice(&jpeg);
        fs::write(&image_path, &image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path,
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let result = carve_evidence_with_protective_limit(
            &case_path,
            evidence_id,
            CarveOptions {
                max_scan_bytes: 0,
                max_files: 0,
            },
            32,
        )?;

        assert_eq!(result.carved_files, 2);
        assert!(result.truncated);
        assert_eq!(result.status, "truncated");
        assert_eq!(result.protective_extent_limit_hits, 1);
        assert_eq!(result.truncation_reasons.len(), 1);
        assert!(result.truncation_reasons[0].contains("32-byte protective limit"));

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let zip = entries
            .iter()
            .find(|entry| entry.name.ends_with(".zip"))
            .expect("bounded ZIP carve");
        assert_eq!(zip.size_bytes, Some(32));
        assert_eq!(
            zip.metadata_json["carve_extent_truncated"].as_bool(),
            Some(true)
        );
        assert_eq!(
            zip.metadata_json["carve_protective_extent_limit_bytes"].as_u64(),
            Some(32)
        );
        assert!(zip.metadata_json["carve_extent_truncation_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("decoded offset 0x25"));
        assert!(entries.iter().any(|entry| entry.name.ends_with(".jpg")));

        let conn = Connection::open(&case_path)?;
        let (job_status, job_error, parameters): (String, Option<String>, String) = conn
            .query_row(
                "SELECT status, error, parameters_json
             FROM evidence_jobs WHERE evidence_id = ?1 AND job_type = 'carve'
             ORDER BY id DESC LIMIT 1",
                [evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        assert_eq!(job_status, "truncated");
        assert!(job_error
            .as_deref()
            .unwrap_or_default()
            .contains("32-byte protective limit"));
        let parameters: serde_json::Value = serde_json::from_str(&parameters)?;
        assert_eq!(parameters["max_files"].as_u64(), Some(0));
        assert!(parameters["effective_max_files"].is_null());
        assert_eq!(parameters["protective_extent_limit_hits"].as_u64(), Some(1));
        assert_eq!(parameters["truncated"].as_bool(), Some(true));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn examiner_carve_file_limit_has_exact_truncated_status_and_reason() -> Result<()> {
        let case_path = unique_case_path("carve-file-limit");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("carve-file-limit-source");
        let image_path = dir.join("carve-file-limit.img");
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, b'x', 0xFF, 0xD9];
        let mut image = vec![0_u8; 512];
        image[32..32 + jpeg.len()].copy_from_slice(&jpeg);
        image[256..256 + jpeg.len()].copy_from_slice(&jpeg);
        fs::write(&image_path, image)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path,
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let result = carve_evidence(
            &case_path,
            evidence_id,
            CarveOptions {
                max_scan_bytes: 0,
                max_files: 1,
            },
        )?;
        assert_eq!(result.carved_files, 1);
        assert!(result.truncated);
        assert_eq!(result.status, "truncated");
        assert_eq!(
            result.truncation_reasons,
            vec!["carving stopped at the examiner-requested 1 file limit"]
        );

        let conn = Connection::open(&case_path)?;
        let (status, error, effective_limit): (String, Option<String>, i64) = conn.query_row(
            "SELECT status, error, json_extract(parameters_json, '$.effective_max_files')
             FROM evidence_jobs WHERE evidence_id = ?1 AND job_type = 'carve'
             ORDER BY id DESC LIMIT 1",
            [evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(status, "truncated");
        assert_eq!(
            error.as_deref(),
            Some("carving stopped at the examiner-requested 1 file limit")
        );
        assert_eq!(effective_limit, 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn indexed_file_hash_uses_all_available_cpu_workers() -> Result<()> {
        let case_path = unique_case_path("parallel-indexed-file-hash");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("parallel-indexed-file-hash-source");
        for index in 0..48_u32 {
            fs::write(
                evidence_dir.join(format!("sample-{index:03}.bin")),
                format!("parallel hash fixture {index:03}").as_bytes(),
            )?;
        }
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;

        let result = hash_indexed_files(
            &case_path,
            HashIndexedFilesOptions {
                evidence_id,
                max_files: 0,
                max_file_bytes: 0,
            },
        )?;
        assert_eq!(result.worker_threads, available_processing_worker_count());
        assert_eq!(result.eligible_files_total, 48);
        assert_eq!(result.up_to_date_files_skipped, 0);
        assert_eq!(result.files_hashed, 48);
        assert_eq!(result.files_skipped, 0);
        assert!(!result.truncated);

        let conn = open_existing_case(&case_path)?;
        let committed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM filesystem_entries
             WHERE evidence_id = ?1
               AND json_extract(metadata_json, '$.file_sha256_analysis') = ?2
               AND length(json_extract(metadata_json, '$.file_sha256')) = 64",
            params![evidence_id, FILE_HASH_CHECKPOINT_VERSION],
            |row| row.get(0),
        )?;
        assert_eq!(committed, 48);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn indexed_file_hash_reuses_only_immutable_image_checkpoints() -> Result<()> {
        let case_path = unique_case_path("indexed-file-hash-checkpoint");
        create_test_case(&case_path)?;
        let image_path = unique_temp_dir("indexed-file-hash-checkpoint-source").join("disk.raw");
        fs::write(&image_path, b"raw image placeholder")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let mut conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json,
                                        started_at, finished_at)
             VALUES (?1, ?2, 'test_index', 'completed', '{}',
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![case_id, evidence_id],
        )?;
        let source_job_id = tx.last_insert_rowid();
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            "/already-hashed.bin",
            "already-hashed.bin",
            "file",
            Some(3),
            &serde_json::json!({
                "file_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "file_sha256_analysis": FILE_HASH_CHECKPOINT_VERSION,
                "file_sha256_input": "complete reconstructed file content"
            })
            .to_string(),
            source_job_id,
        )?;
        tx.commit()?;
        drop(conn);

        let result = hash_indexed_files(
            &case_path,
            HashIndexedFilesOptions {
                evidence_id,
                max_files: 0,
                max_file_bytes: 0,
            },
        )?;
        assert_eq!(result.eligible_files_total, 1);
        assert_eq!(result.up_to_date_files_skipped, 1);
        assert_eq!(result.files_hashed, 0);
        assert_eq!(result.files_skipped, 0);
        assert!(!result.truncated);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(image_path.parent().unwrap());
        Ok(())
    }

    #[test]
    fn hash_evidence_records_sha256_and_fills_report() -> Result<()> {
        let case_path = unique_case_path("hash-evidence");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("hash-evidence-source");

        // Split raw: the hash must cover the DECODED stream (all segments).
        fs::write(dir.join("disk.001"), b"abc")?;
        fs::write(dir.join("disk.002"), b"defg")?;
        fs::write(dir.join("disk.003"), b"hi")?;
        let image_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("disk.001"),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let result = hash_evidence(&case_path, image_id)?;
        assert_eq!(result.bytes_hashed, 9);
        assert_eq!(
            result.sha256_hex,
            "19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f"
        );
        assert_eq!(result.sha256_scope, "logical_media");
        let manifest = result
            .acquisition_manifest_json
            .as_ref()
            .expect("split acquisition manifest");
        assert_eq!(manifest.scheme, "split_raw_segments");
        assert!(manifest.complete);
        assert_eq!(manifest.segment_count, 3);
        assert_eq!(manifest.total_size, 9);
        assert_eq!(
            manifest
                .segments
                .iter()
                .map(|segment| (segment.size, segment.sha256.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    3,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                ),
                (
                    4,
                    "4c8a43980498636e9c1d1595fa5d115af7937c2422dfe68a2520a52b7a5fb4de"
                ),
                (
                    2,
                    "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
                ),
            ]
        );
        assert!(!result.hashed_at.is_empty());

        let evidence = list_evidence(&case_path)?;
        assert_eq!(
            evidence[0].sha256_hex.as_deref(),
            Some(result.sha256_hex.as_str())
        );
        assert!(evidence[0].hashed_at.is_some());
        assert_eq!(evidence[0].sha256_scope.as_deref(), Some("logical_media"));
        assert_eq!(
            evidence[0].acquisition_manifest_json.as_ref(),
            Some(manifest)
        );

        // The report's evidence table now carries the stored hash.
        let report = report_data(&case_path)?;
        assert_eq!(
            report.evidence[0].sha256.as_deref(),
            Some(result.sha256_hex.as_str())
        );
        let html = render_report_html(&report);
        assert!(html.contains(&result.sha256_hex));
        assert!(!html.contains("not computed"));

        // Plain file evidence hashes its bytes directly.
        fs::write(dir.join("doc.txt"), b"hello evidence")?;
        let file_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("doc.txt"),
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let file_hash = hash_evidence(&case_path, file_id)?;
        assert_eq!(
            file_hash.sha256_hex,
            "9af4c73b2a919f220f4b008e466b52808a1987122d95ff0f2dde00968e36e844"
        );
        assert_eq!(file_hash.sha256_scope, "file");
        assert!(file_hash.acquisition_manifest_json.is_none());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn fixed_vhd_hash_reports_distinct_known_media_and_container_identities() -> Result<()> {
        const DECODED_SHA256: &str =
            "01a855a9f28f8531b73dddd9baac2b6bebfed515117fcf735f7779d19f28cf92";
        const CONTAINER_SHA256: &str =
            "ef4546a049acfd2d09f84721c908ec8afd9aabd74b6fbb81a8713b41eee03dd2";

        let case_path = unique_case_path("hash-fixed-vhd-known-answer");
        create_test_case(&case_path)?;
        let dir = unique_temp_dir("hash-fixed-vhd-known-answer-source");
        let image_path = dir.join("known.vhd");
        create_test_fixed_vhd_image(&image_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let result = hash_evidence(&case_path, evidence_id)?;
        assert_eq!(result.bytes_hashed, 4_194_304);
        assert_eq!(result.sha256_hex, DECODED_SHA256);
        assert_eq!(result.sha256_scope, "logical_media");
        let manifest = result
            .acquisition_manifest_json
            .as_ref()
            .expect("fixed VHD acquisition manifest");
        assert_eq!(manifest.scheme, "single_container_file");
        assert!(manifest.complete);
        assert_eq!(manifest.segment_count, 1);
        assert_eq!(manifest.total_size, 4_194_816);
        assert_eq!(manifest.segments[0].size, 4_194_816);
        assert_eq!(manifest.segments[0].sha256, CONTAINER_SHA256);
        assert_eq!(manifest.segments[0].path, stable_path_string(&image_path));

        let bookmark_id = create_test_bookmark(&case_path)?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("Known VHD finding".to_string()),
                logical_path: Some("/known/finding.bin".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({
                    "kind": "filesystem_entry",
                    "logical_path": "/known/finding.bin",
                    "evidence_sha256_hex": DECODED_SHA256,
                }),
            },
        )?;

        let report = report_data(&case_path)?;
        assert_eq!(
            report.evidence[0].sha256_scope.as_deref(),
            Some("logical_media")
        );
        assert_eq!(
            report.evidence[0]
                .acquisition_manifest_json
                .as_ref()
                .and_then(|manifest| manifest.segments.first())
                .map(|segment| segment.sha256.as_str()),
            Some(CONTAINER_SHA256)
        );
        let html = render_report_html(&report);
        assert!(html.contains("SHA-256 (decoded media for images; evidence file for files)"));
        assert!(html.contains("Logical media SHA-256 (decoded image stream)"));
        assert!(html.contains("Acquisition/container file SHA-256"));
        assert!(html.contains(DECODED_SHA256));
        assert!(html.contains(CONTAINER_SHA256));
        assert_ne!(DECODED_SHA256, CONTAINER_SHA256);

        let conn = open_existing_case(&case_path)?;
        let audit: String = conn.query_row(
            "SELECT details_json FROM audit_events
             WHERE event_type = 'evidence.hash' AND object_id = ?1
             ORDER BY id DESC LIMIT 1",
            params![evidence_id],
            |row| row.get(0),
        )?;
        let audit: serde_json::Value = serde_json::from_str(&audit)?;
        assert_eq!(audit["logical_media_sha256"], DECODED_SHA256);
        assert_eq!(
            audit["acquisition_manifest_json"]["segments"][0]["sha256"],
            CONTAINER_SHA256
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_deleted_fat_entries() -> Result<()> {
        let case_path = unique_case_path("image-fat-deleted");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-fat-deleted-source");
        let image_path = evidence_dir.join("fat-deleted.img");

        // Build a FAT volume with a live file plus SECRET.TXT, then flip
        // SECRET.TXT's directory entry to 0xE5 without touching its data -
        // exactly what an ordinary delete leaves on disk.
        let payload = b"deleted fat payload";
        let mut volume = {
            let mut cursor = io::Cursor::new(vec![0_u8; 1024 * 1024]);
            fatfs::format_volume(&mut cursor, fatfs::FormatVolumeOptions::new())?;
            cursor.seek(SeekFrom::Start(0))?;
            {
                let fs = fatfs::FileSystem::new(&mut cursor, fatfs::FsOptions::new())?;
                let root = fs.root_dir();
                let mut live = root.create_file("keep.txt")?;
                live.write_all(b"live file")?;
                live.flush()?;
                let mut secret = root.create_file("secret.txt")?;
                secret.write_all(payload)?;
                secret.flush()?;
            }
            cursor.into_inner()
        };
        let marker = b"SECRET  TXT";
        let position = volume
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("SECRET.TXT directory entry present");
        volume[position] = 0xE5;
        fs::write(&image_path, &volume)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let deleted = entries
            .iter()
            .find(|entry| {
                entry.is_deleted
                    && entry.metadata_json["recovery_source"].as_str()
                        == Some("fat_directory_entry")
            })
            .expect("deleted FAT entry should be indexed");
        assert!(deleted.name.starts_with('_'));
        assert!(deleted.name.ends_with(".TXT"));
        assert!(deleted.logical_path.contains("/Recovery/Deleted Files/"));
        assert_eq!(deleted.size_bytes, Some(payload.len() as i64));
        assert_eq!(
            deleted.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            deleted.metadata_json["category_sub"].as_str(),
            Some("Deleted files")
        );
        assert!(deleted.metadata_json["file_data_physical_offset"].is_u64());
        // The fixture's fatfs build writes zeroed DOS timestamps, so
        // modified_utc is absent here; real volumes carry it.

        // The deleted file's content is recoverable byte-for-byte.
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: deleted.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, payload);
        assert!(bytes.eof);

        // Live files are untouched by the deleted scan.
        assert!(entries
            .iter()
            .any(|entry| { entry.logical_path.ends_with("/keep.txt") && !entry.is_deleted }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_recovers_lost_partition_from_wiped_table() -> Result<()> {
        let case_path = unique_case_path("image-lost-partition");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-lost-partition-source");
        let image_path = evidence_dir.join("wiped-table.img");
        // Deleted-partition scenario: sector 0 zeroed (no MBR/GPT), orphaned
        // FAT volume at 2 MiB inside unpartitioned space.
        let fat_volume = test_fat_volume_bytes()?;
        let volume_offset = 2 * 1024 * 1024;
        let mut image = vec![0_u8; volume_offset + fat_volume.len() + 512];
        // A stray EF53 sequence with deliberately overflowing EXT geometry
        // appears before the real orphaned FAT volume. Candidate validation
        // must reject it and continue scanning instead of rolling back the
        // valid recovery work with "ext volume byte length overflow".
        let false_ext_offset = 512_usize;
        image[false_ext_offset + 0x438..false_ext_offset + 0x43A]
            .copy_from_slice(&0xEF53_u16.to_le_bytes());
        image[false_ext_offset + 0x418..false_ext_offset + 0x41C]
            .copy_from_slice(&6_u32.to_le_bytes());
        image[false_ext_offset + 0x404..false_ext_offset + 0x408]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        image[false_ext_offset + 0x460..false_ext_offset + 0x464]
            .copy_from_slice(&0x80_u32.to_le_bytes());
        image[false_ext_offset + 0x550..false_ext_offset + 0x554]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        image[volume_offset..volume_offset + fat_volume.len()].copy_from_slice(&fat_volume);
        fs::write(&image_path, image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Image,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 200,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let record = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("recovered_partition")
            })
            .expect("recovered partition record should be indexed");
        assert_eq!(
            record.metadata_json["start_offset"].as_u64(),
            Some(volume_offset as u64)
        );
        assert_eq!(
            record.metadata_json["detected_filesystem"].as_str(),
            Some("FAT")
        );
        assert_eq!(
            record.metadata_json["recovery_source"].as_str(),
            Some("boot_sector_scan")
        );
        assert_eq!(
            record.metadata_json["category_main"].as_str(),
            Some("Recovery")
        );
        assert_eq!(
            record.metadata_json["category_sub"].as_str(),
            Some("Recovered partitions")
        );
        assert!(!entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("recovered_partition")
                && entry.metadata_json["detected_filesystem"].as_str() == Some("EXT")
        }));

        // The orphaned volume's contents are browsable and readable.
        let note = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/recovered-01-fat/DFIR/note.txt"
            })
            .expect("file inside recovered volume should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_whole_fat_volume_without_partition_table() -> Result<()> {
        let case_path = unique_case_path("image-whole-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-whole-fat-source");
        let image_path = evidence_dir.join("whole-fat.img");
        create_test_whole_fat_image(&image_path)?;
        // Append a second valid FAT boot sector inside bytes beyond the
        // primary volume. A whole-volume acquisition recognized at offset 0
        // must not be rescanned internally as a lost-partition gap.
        let nested_volume = test_fat_volume_bytes()?;
        let nested_offset = 2 * 1024 * 1024;
        let mut image = fs::read(&image_path)?;
        image.resize(nested_offset + nested_volume.len() + 512, 0);
        image[nested_offset..nested_offset + nested_volume.len()].copy_from_slice(&nested_volume);
        fs::write(&image_path, image)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(!entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("recovered_partition")
        }));
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/000-whole-image"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("fatfs")
        }));
        let note = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/DFIR/note.txt"
            })
            .expect("whole-image FAT file should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_whole_ntfs_volume_when_fixture_available() -> Result<()> {
        let Some(fixture_path) = optional_ntfs_testfs1_path() else {
            eprintln!("skipping NTFS fixture test; ntfs crate testfs1 fixture not found");
            return Ok(());
        };
        let case_path = unique_case_path("image-whole-ntfs");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-whole-ntfs-source");
        let image_path = evidence_dir.join("whole-ntfs.img");
        fs::copy(&fixture_path, &image_path).with_context(|| {
            format!(
                "copying NTFS fixture {} to {}",
                fixture_path.display(),
                image_path.display()
            )
        })?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 2_000,
            },
        )?;
        assert!(
            matches!(processed.status.as_str(), "completed" | "truncated"),
            "unexpected NTFS processing status: {}",
            processed.status
        );
        // A damaged directory index may still yield an explicit partial status,
        // but it must no longer be the sole source of the visible hierarchy:
        // the allocated $MFT reconciliation pass runs before deleted-record
        // inventory and restores records whose parent references remain valid.

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Volumes/000-whole-image"
                && entry.entry_kind == "directory"
                && entry.metadata_json["filesystem_parser"].as_str() == Some("ntfs")
        }));
        let file = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/file-with-12345"
            })
            .expect("NTFS resident data file should be indexed");
        assert_eq!(file.entry_kind, "file");
        assert!(file.metadata_json["ntfs_file_record_number"]
            .as_u64()
            .is_some());
        assert_eq!(
            file.metadata_json["mft_metadata_parser"].as_str(),
            Some("mft crate 0.7.0")
        );
        assert_eq!(
            file.metadata_json["mft_parser_record"]["record_number"].as_u64(),
            file.metadata_json["ntfs_file_record_number"].as_u64()
        );
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: file.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"12345");
        assert_eq!(bytes.total_size, 5);

        let unallocated = entries
            .iter()
            .find(|entry| {
                entry.logical_path == "/Image Analysis/Volumes/000-whole-image/UnallocatedSpace"
            })
            .expect("NTFS unallocated-space row should be indexed from $Bitmap");
        assert_eq!(unallocated.entry_kind, "file");
        assert_eq!(
            unallocated.metadata_json["artifact_kind"].as_str(),
            Some("unallocated_space")
        );
        assert_eq!(
            unallocated.metadata_json["storage_area"].as_str(),
            Some("unallocated_space")
        );
        assert!(unallocated.size_bytes.unwrap_or_default() > 0);
        assert!(
            unallocated.metadata_json["unallocated_run_count"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        let unallocated_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: unallocated.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(
            unallocated_bytes.total_size,
            unallocated.size_bytes.unwrap_or_default() as u64
        );
        assert!(unallocated_bytes.bytes_read > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_analyzes_fixed_vhd_partition_records() -> Result<()> {
        let case_path = unique_case_path("image-vhd");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-vhd-source");
        let image_path = evidence_dir.join("disk.vhd");
        create_test_fixed_vhd_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let container = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Container.record")
            .expect("container record should be created");
        assert_eq!(
            container.metadata_json["container_format"].as_str(),
            Some("Vhd")
        );
        assert!(entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("disk_partition")
                && entry.metadata_json["start_offset"].as_u64() == Some(1_048_576)
        }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn image_process_indexes_fat_entries_inside_fixed_vhd() -> Result<()> {
        let case_path = unique_case_path("image-vhd-fat");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("image-vhd-fat-source");
        let image_path = evidence_dir.join("fat-disk.vhd");
        create_test_fat_fixed_vhd_image(&image_path)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: image_path.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.logical_path == "/Image Analysis/Container.record"
                && entry.metadata_json["container_format"].as_str() == Some("Vhd")
        }));
        let note = entries
            .iter()
            .find(|entry| entry.logical_path == "/Image Analysis/Volumes/001-part0/DFIR/note.txt")
            .expect("FAT file inside fixed VHD should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: note.id,
                offset: 0,
                length: 64,
            },
        )?;
        assert_eq!(bytes.bytes, b"FAT evidence artifact");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evaluate_signature_classifies_headers_against_extension() {
        // JPEG bytes with a .jpg name -> canonical match.
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let f = evaluate_signature("photo.jpg", &jpeg);
        assert_eq!(f.status, "match");
        assert_eq!(f.detected_label, Some("JPEG"));
        assert_eq!(f.extension.as_deref(), Some("jpg"));

        // Same JPEG bytes with a .txt name -> mismatch (renamed extension).
        let f = evaluate_signature("secret.txt", &jpeg);
        assert_eq!(f.status, "mismatch");
        assert_eq!(f.detected_label, Some("JPEG"));

        // JPEG bytes with .jpeg -> alias (legit alternate extension).
        let f = evaluate_signature("photo.jpeg", &jpeg);
        assert_eq!(f.status, "alias");

        // PNG bytes with .png -> match.
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(evaluate_signature("a.png", &png).status, "match");

        // Unrecognized header with an extension -> unknown.
        let f = evaluate_signature("notes.dat", b"just some ascii text here");
        assert_eq!(f.status, "unknown");
        assert_eq!(f.detected_label, None);

        // No extension -> no_extension regardless of content.
        assert_eq!(evaluate_signature("README", &jpeg).status, "no_extension");
        // Dotfiles have no real extension.
        assert_eq!(evaluate_signature(".bashrc", b"x").status, "no_extension");

        // ZIP container with an Office Open XML extension -> alias, not mismatch.
        let zip = [0x50, 0x4B, 0x03, 0x04];
        assert_eq!(evaluate_signature("report.docx", &zip).status, "alias");
        // ZIP container renamed to .jpg -> mismatch.
        assert_eq!(evaluate_signature("hidden.jpg", &zip).status, "mismatch");

        let invoice = b"Date,Vendor,Amount,Status\r\n2026-01-04,Acme,125.00,Paid\r\n2026-02-07,Globex,88.10,Pending\r\n2026-03-11,Initech,42.00,Paid\r\n";
        let disguised_invoice = evaluate_signature("invoice.pdf", invoice);
        assert_eq!(disguised_invoice.status, "mismatch");
        assert_eq!(disguised_invoice.detected_label, Some("CSV"));
        assert_eq!(
            disguised_invoice.mismatch_basis,
            Some("detected_type_conflicts_with_extension")
        );
        assert_eq!(evaluate_signature("invoice.csv", invoice).status, "match");
        assert_eq!(evaluate_signature("invoice.dat", invoice).status, "unknown");

        let valid_pdf = b"leading comment\r\n%PDF-1.7\r\n";
        assert_eq!(evaluate_signature("valid.pdf", valid_pdf).status, "match");
        assert_eq!(
            evaluate_signature_with_completeness("partial.pdf", b"partial", false).status,
            "unknown"
        );
    }

    #[test]
    fn analyze_signatures_flags_renamed_extension() -> Result<()> {
        let case_path = unique_case_path("signature-analysis");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("signature-analysis-source");
        fs::create_dir_all(&evidence_dir)?;
        // A real JPEG (magic FF D8 FF) deliberately misnamed with a .txt extension.
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        jpeg.extend_from_slice(&[0u8; 64]);
        fs::write(evidence_dir.join("disguised.txt"), &jpeg)?;
        // A genuine text file with a .txt extension -> unknown (no signature), not a mismatch.
        fs::write(
            evidence_dir.join("real.txt"),
            b"just plain notes, nothing to detect",
        )?;
        fs::write(
            evidence_dir.join("invoice.pdf"),
            b"Date,Vendor,Amount,Status\r\n2026-01-04,Acme,125.00,Paid\r\n2026-02-07,Globex,88.10,Pending\r\n2026-03-11,Initech,42.00,Paid\r\n",
        )?;
        // A PNG correctly named.
        let png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
        ];
        fs::write(evidence_dir.join("ok.png"), png)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 100,
            },
        )?;
        assert_eq!(result.status, "completed");
        assert!(!result.truncated);
        assert!(result.files_examined >= 3);
        assert_eq!(
            result.mismatches, 2,
            "the renamed JPEG and CSV-backed PDF should be flagged"
        );
        assert!(result.matches >= 1, "the PNG should match");

        // Verify the metadata was actually written back onto the disguised file.
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let disguised = entries
            .iter()
            .find(|e| e.logical_path.ends_with("/disguised.txt"))
            .expect("disguised.txt should be indexed");
        assert_eq!(
            disguised.metadata_json.get("signature_status"),
            Some(&serde_json::Value::String("mismatch".to_string()))
        );
        assert_eq!(
            disguised.metadata_json.get("detected_signature"),
            Some(&serde_json::Value::String("JPEG".to_string()))
        );
        assert_eq!(
            disguised.metadata_json.get("file_extension"),
            Some(&serde_json::Value::String("txt".to_string()))
        );

        let real = entries
            .iter()
            .find(|e| e.logical_path.ends_with("/real.txt"))
            .expect("real.txt should be indexed");
        assert_eq!(
            real.metadata_json.get("signature_status"),
            Some(&serde_json::Value::String("unknown".to_string()))
        );

        let invoice = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/invoice.pdf"))
            .expect("invoice.pdf should be indexed");
        assert_eq!(
            invoice.metadata_json["signature_status"].as_str(),
            Some("mismatch")
        );
        assert_eq!(
            invoice.metadata_json["detected_signature"].as_str(),
            Some("CSV")
        );
        assert_eq!(
            invoice.metadata_json["expected_signature"].as_str(),
            Some("PDF")
        );
        assert_eq!(
            invoice.metadata_json["signature_detection_basis"].as_str(),
            Some("content_heuristic")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn signature_analysis_keyset_pages_cover_every_candidate_once() -> Result<()> {
        let file_count = SIGNATURE_ANALYSIS_PAGE_SIZE * 2 + 7;
        let (case_path, evidence_dir, evidence_id) =
            create_signature_analysis_test_evidence("signature-keyset", file_count)?;
        let before_paths: Vec<String> = {
            let conn = open_existing_case(&case_path)?;
            let mut stmt = conn.prepare(
                "SELECT logical_path FROM filesystem_entries
                 WHERE evidence_id = ?1 AND entry_kind = 'file'
                 ORDER BY evidence_id, logical_path, id",
            )?;
            let rows = stmt.query_map(params![evidence_id], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(before_paths.len(), file_count);

        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 0,
            },
        )?;
        assert_eq!(result.status, "completed");
        assert!(!result.truncated);
        assert_eq!(result.candidates_total, file_count);
        assert_eq!(result.candidates_processed, file_count);
        assert_eq!(result.files_examined, file_count);
        assert_eq!(result.files_skipped, 0);
        assert_eq!(result.matches, file_count);
        assert_eq!(result.errors.len(), 0);

        let conn = open_existing_case(&case_path)?;
        let analyzed_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM filesystem_entries
             WHERE evidence_id = ?1 AND entry_kind = 'file'
               AND json_extract(metadata_json, '$.signature_analysis') = 'signature_magic_and_text_v2'",
            params![evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(usize::try_from(analyzed_count)?, file_count);
        let after_paths: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT logical_path FROM filesystem_entries
                 WHERE evidence_id = ?1 AND entry_kind = 'file'
                 ORDER BY evidence_id, logical_path, id",
            )?;
            let rows = stmt.query_map(params![evidence_id], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(after_paths, before_paths, "canonical paths must not change");
        drop(conn);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn signature_analysis_reuses_captured_header_without_reopening_source() -> Result<()> {
        let case_path = unique_case_path("signature-captured-header");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("signature-captured-header-source");
        fs::create_dir_all(&evidence_dir)?;
        let source = evidence_dir.join("captured.exe");
        fs::write(&source, b"MZ captured executable header")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        let captured_bytes: i64 = open_existing_case(&case_path)?.query_row(
            "SELECT length(content_head) FROM filesystem_entries
             WHERE evidence_id = ?1 AND name = 'captured.exe'",
            params![evidence_id],
            |row| row.get(0),
        )?;
        assert!(captured_bytes >= 2);

        // The cached index head is sufficient for verification; this also proves the optimized
        // path does not silently fall back to the now-unavailable original folder source.
        fs::remove_file(&source)?;
        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 0,
            },
        )?;
        assert_eq!(result.status, "completed");
        assert_eq!(result.files_examined, 1);
        assert_eq!(result.unreadable, 0);
        assert_eq!(result.matches, 1);

        let resumed = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 0,
            },
        )?;
        assert_eq!(resumed.eligible_files_total, 1);
        assert_eq!(resumed.candidates_total, 0);
        assert_eq!(resumed.candidates_processed, 0);
        assert_eq!(resumed.up_to_date_files_skipped, 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn signature_analysis_positive_limit_is_exact_across_pages() -> Result<()> {
        let file_count = SIGNATURE_ANALYSIS_PAGE_SIZE + 11;
        let exact_limit = SIGNATURE_ANALYSIS_PAGE_SIZE + 3;
        let (case_path, evidence_dir, evidence_id) =
            create_signature_analysis_test_evidence("signature-exact-limit", file_count)?;
        let expected_paths: Vec<String> = {
            let conn = open_existing_case(&case_path)?;
            let mut stmt = conn.prepare(
                "SELECT logical_path FROM filesystem_entries
                 WHERE evidence_id = ?1 AND entry_kind = 'file'
                 ORDER BY evidence_id, logical_path, id
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![evidence_id, i64::try_from(exact_limit)?], |row| {
                    row.get(0)
                })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };

        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: exact_limit,
            },
        )?;
        assert_eq!(result.status, "truncated");
        assert!(result.truncated);
        assert_eq!(result.candidates_total, file_count);
        assert_eq!(result.candidates_processed, exact_limit);
        assert_eq!(result.files_examined, exact_limit);
        assert_eq!(result.matches, exact_limit);

        let conn = open_existing_case(&case_path)?;
        let analyzed_paths: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT logical_path FROM filesystem_entries
                 WHERE evidence_id = ?1
                   AND json_extract(metadata_json, '$.signature_analysis') = 'signature_magic_and_text_v2'
                 ORDER BY evidence_id, logical_path, id",
            )?;
            let rows = stmt.query_map(params![evidence_id], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(analyzed_paths, expected_paths);
        let (job_status, job_error, parameters): (String, Option<String>, String) = conn
            .query_row(
                "SELECT status, error, parameters_json FROM evidence_jobs WHERE id = ?1",
                params![result.job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        assert_eq!(job_status, "truncated");
        assert!(job_error
            .unwrap_or_default()
            .contains("entry limit reached"));
        let parameters: serde_json::Value = serde_json::from_str(&parameters)?;
        assert_eq!(parameters["max_entries"].as_u64(), Some(exact_limit as u64));
        assert_eq!(
            parameters["candidates_processed"].as_u64(),
            Some(exact_limit as u64)
        );
        drop(conn);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn signature_analysis_discloses_entry_and_database_errors() -> Result<()> {
        let (case_path, evidence_dir, evidence_id) =
            create_signature_analysis_test_evidence("signature-errors", 3)?;
        let entries: Vec<(i64, String, String)> = {
            let conn = open_existing_case(&case_path)?;
            let mut stmt = conn.prepare(
                "SELECT id, name, logical_path FROM filesystem_entries
                 WHERE evidence_id = ?1 AND entry_kind = 'file'
                 ORDER BY evidence_id, logical_path, id",
            )?;
            let rows = stmt.query_map(params![evidence_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(entries.len(), 3);
        {
            let conn = open_existing_case(&case_path)?;
            conn.execute(
                "UPDATE filesystem_entries SET metadata_json = '[]' WHERE id = ?1",
                params![entries[0].0],
            )?;
        }
        fs::remove_file(evidence_dir.join(&entries[1].1))?;

        let result = analyze_signatures(
            &case_path,
            AnalyzeSignaturesOptions {
                evidence_id: Some(evidence_id),
                max_entries: 0,
            },
        )?;
        assert_eq!(result.status, "truncated");
        assert!(result.truncated);
        assert_eq!(result.candidates_total, 3);
        assert_eq!(result.candidates_processed, 3);
        assert_eq!(result.files_examined, 1);
        assert_eq!(result.files_skipped, 2);
        assert_eq!(result.metadata_parse_errors, 1);
        assert_eq!(result.unreadable, 1);
        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.errors_omitted, 0);
        assert!(result
            .errors
            .iter()
            .any(|message| message.contains(&entries[0].2) && message.contains("not an object")));
        assert!(result.errors.iter().any(|message| {
            message.contains(&entries[1].2) && message.contains("unable to read signature header")
        }));

        let conn = open_existing_case(&case_path)?;
        let (job_status, job_error, parameters): (String, Option<String>, String) = conn
            .query_row(
                "SELECT status, error, parameters_json FROM evidence_jobs WHERE id = ?1",
                params![result.job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        assert_eq!(job_status, "truncated");
        let job_error = job_error.unwrap_or_default();
        assert!(job_error.contains("could not be read"));
        assert!(job_error.contains("invalid JSON objects"));
        let parameters: serde_json::Value = serde_json::from_str(&parameters)?;
        assert_eq!(parameters["errors"].as_array().map(Vec::len), Some(2));
        drop(conn);

        let database_error = write_signature_analysis_updates(
            &case_path,
            active_case_id(&open_existing_case(&case_path)?)?,
            &[(i64::MAX, "{}".to_string())],
        )
        .expect_err("a nonexistent entry update must be an explicit database error");
        let database_error = format!("{database_error:#}");
        assert!(database_error.contains("affected 0 rows"));
        let failed_job_id = {
            let conn = open_existing_case(&case_path)?;
            let case_id = active_case_id(&conn)?;
            conn.execute(
                "INSERT INTO evidence_jobs(
                     case_id, evidence_id, job_type, status, parameters_json, started_at
                 ) VALUES (?1, ?2, 'signature_analysis', 'running', '{}',
                           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![case_id, evidence_id],
            )?;
            conn.last_insert_rowid()
        };
        let failed_stats = SignatureAnalysisStats {
            candidates_processed: 2,
            files_examined: 2,
            ..SignatureAnalysisStats::default()
        };
        mark_signature_analysis_failed(&case_path, failed_job_id, &database_error, &failed_stats)?;
        let conn = open_existing_case(&case_path)?;
        let (failed_status, failed_error, failed_parameters): (String, String, String) = conn
            .query_row(
                "SELECT status, error, parameters_json FROM evidence_jobs WHERE id = ?1",
                params![failed_job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        assert_eq!(failed_status, "failed");
        assert!(failed_error.contains("affected 0 rows"));
        let failed_parameters: serde_json::Value = serde_json::from_str(&failed_parameters)?;
        assert_eq!(failed_parameters["candidates_processed"].as_u64(), Some(2));
        drop(conn);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    fn create_signature_analysis_test_evidence(
        label: &str,
        file_count: usize,
    ) -> Result<(PathBuf, PathBuf, i64)> {
        let case_path = unique_case_path(label);
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir(&format!("{label}-source"));
        fs::create_dir_all(&evidence_dir)?;
        let png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
        ];
        for index in 0..file_count {
            fs::write(evidence_dir.join(format!("file-{index:05}.png")), png)?;
        }
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(!processed.truncated);
        Ok((case_path, evidence_dir, evidence_id))
    }

    #[test]
    fn category_entry_counts_groups_stored_categories() -> Result<()> {
        let case_path = unique_case_path("category-counts");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("category-counts-source");
        let nested = evidence_dir.join("Docs");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("notes.txt"), b"plain text notes")?;
        fs::write(nested.join("report.pdf"), b"%PDF-1.4 tiny test body")?;
        fs::write(evidence_dir.join("tool.exe"), b"MZ fake executable")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        // The migration must have created the per-evidence count index.
        let conn = open_existing_case(&case_path)?;
        let index_present: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'ix_filesystem_entries_case_evidence'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(index_present, 1);
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, '/legacy/Parser Errors/error.record',
                       'Legacy Parser Diagnostic', 'record', ?3)",
            params![
                active_case_id(&conn)?,
                evidence_id,
                serde_json::json!({
                    "artifact_kind": "filesystem_parser_error",
                    "category_hidden": false,
                    "category_main": "Analysis Diagnostics",
                    "category_sub": "Parser errors",
                })
                .to_string(),
            ],
        )?;
        drop(conn);

        let counts = category_entry_counts(&case_path)?;
        let find = |main: &str, sub: &str| {
            counts
                .iter()
                .find(|row| row.main == main && row.sub == sub)
                .map(|row| row.count)
                .unwrap_or(0)
        };
        assert_eq!(find("Documents and Office", "Text and notes"), 1);
        assert_eq!(find("Documents and Office", "PDF"), 1);
        assert_eq!(find("Program Execution", "Executables and binaries"), 1);
        assert_eq!(find("Analysis Diagnostics", "Parser errors"), 0);

        // Counts cover exactly the non-directory entries: the Docs folder row
        // must not contribute.
        let total: i64 = counts.iter().map(|row| row.count).sum();
        let file_entries = list_filesystem_entries(&case_path, Some(evidence_id))?
            .into_iter()
            .filter(|entry| {
                entry.entry_kind != "directory"
                    && !matches!(
                        entry.metadata_json["artifact_kind"].as_str(),
                        Some("filesystem_parser_error" | "filesystem_parser_summary")
                    )
            })
            .count() as i64;
        assert_eq!(total, file_entries);
        assert!(counts
            .iter()
            .all(|row| !row.main.is_empty() && row.count > 0));
        assert!(max_filesystem_entry_id(&case_path)? > 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn list_entries_by_category_pages_files_only_and_counts_total() -> Result<()> {
        let case_path = unique_case_path("category-page");
        create_test_case(&case_path)?;
        let first_source = unique_temp_dir("category-page-source-a");
        let second_source = unique_temp_dir("category-page-source-b");
        fs::write(first_source.join("placeholder-a.bin"), b"a")?;
        fs::write(second_source.join("placeholder-b.bin"), b"b")?;
        let first_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: first_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let second_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: second_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let insert_entry = |evidence_id: i64,
                            logical_path: &str,
                            name: &str,
                            entry_kind: &str,
                            metadata: serde_json::Value|
         -> Result<()> {
            conn.execute(
                "INSERT INTO filesystem_entries(
                     case_id, evidence_id, logical_path, name, entry_kind, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    case_id,
                    evidence_id,
                    logical_path,
                    name,
                    entry_kind,
                    metadata.to_string()
                ],
            )?;
            Ok(())
        };
        let docs = serde_json::json!({
            "category_main": "Documents and Office",
            "category_sub": "Word processing"
        });
        insert_entry(
            first_evidence_id,
            "/docs",
            "docs",
            "directory",
            docs.clone(),
        )?;
        insert_entry(
            first_evidence_id,
            "/docs/a.docx",
            "a.docx",
            "file",
            docs.clone(),
        )?;
        insert_entry(
            first_evidence_id,
            "/docs/b.docx",
            "b.docx",
            "file",
            docs.clone(),
        )?;
        insert_entry(
            first_evidence_id,
            "/docs/c.docx",
            "c.docx",
            "file",
            docs.clone(),
        )?;
        insert_entry(
            first_evidence_id,
            "/docs/z-General.zip",
            "z-General.zip",
            "file",
            serde_json::json!({
                "category_main": "Documents and Office",
                "category_sub": "Word processing",
                "file_extension": "zip"
            }),
        )?;
        insert_entry(
            second_evidence_id,
            "/docs/d.docx",
            "d.docx",
            "file",
            docs.clone(),
        )?;
        insert_entry(
            first_evidence_id,
            "/bin/tool.exe",
            "tool.exe",
            "file",
            serde_json::json!({
                "category_main": "Program Execution",
                "category_sub": "Executables and binaries"
            }),
        )?;
        insert_entry(
            first_evidence_id,
            "/cloud/sync.txt",
            "sync.txt",
            "file",
            serde_json::json!({
                "category_main": "Cloud and Web",
                "category_sub": "Cloud sync"
            }),
        )?;
        insert_entry(
            first_evidence_id,
            "/unknown.bin",
            "unknown.bin",
            "file",
            serde_json::json!({}),
        )?;
        insert_entry(
            first_evidence_id,
            "/null.bin",
            "null.bin",
            "file",
            serde_json::json!({
                "category_main": null,
                "category_sub": null
            }),
        )?;
        drop(conn);

        let first_page = list_entries_by_category(
            &case_path,
            Some(first_evidence_id),
            "Documents and Office",
            Some("Word processing"),
            2,
            0,
        )?;
        assert_eq!(first_page.total_in_category, 4);
        assert_eq!(first_page.total_matching, 4);
        assert_eq!(first_page.entries.len(), 2);
        assert_eq!(
            first_page
                .entries
                .iter()
                .map(|entry| entry.logical_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/docs/a.docx", "/docs/b.docx"]
        );
        assert!(first_page
            .entries
            .iter()
            .all(|entry| entry.entry_kind != "directory"));

        let second_page = list_entries_by_category(
            &case_path,
            Some(first_evidence_id),
            "Documents and Office",
            Some("Word processing"),
            2,
            2,
        )?;
        assert_eq!(second_page.total_in_category, 4);
        assert_eq!(second_page.entries.len(), 2);
        assert_eq!(second_page.entries[0].logical_path, "/docs/c.docx");

        let filtered_zip = list_entries_by_category_filtered(
            &case_path,
            Some(first_evidence_id),
            "Documents and Office",
            Some("Word processing"),
            &CategoryEntryFilters {
                extension: Some("zip".to_string()),
                ..CategoryEntryFilters::default()
            },
            None,
            1,
            0,
        )?;
        assert_eq!(filtered_zip.total_in_category, 4);
        assert_eq!(filtered_zip.total_matching, 1);
        assert_eq!(filtered_zip.entries[0].logical_path, "/docs/z-General.zip");
        assert!(filtered_zip.next_cursor.is_none());

        let cursor_first = list_entries_by_category_filtered(
            &case_path,
            Some(first_evidence_id),
            "Documents and Office",
            Some("Word processing"),
            &CategoryEntryFilters::default(),
            None,
            2,
            0,
        )?;
        let cursor_second = list_entries_by_category_filtered(
            &case_path,
            Some(first_evidence_id),
            "Documents and Office",
            Some("Word processing"),
            &CategoryEntryFilters::default(),
            cursor_first.next_cursor.as_ref(),
            2,
            0,
        )?;
        assert_eq!(
            cursor_second
                .entries
                .iter()
                .map(|entry| entry.logical_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/docs/c.docx", "/docs/z-General.zip"]
        );
        assert!(cursor_second.next_cursor.is_none());

        let all_evidence_docs = list_entries_by_category(
            &case_path,
            None,
            "Documents and Office",
            Some("Word processing"),
            10,
            0,
        )?;
        assert_eq!(all_evidence_docs.total_in_category, 5);

        let uncategorized = list_entries_by_category(
            &case_path,
            Some(first_evidence_id),
            "Uncategorized",
            Some(""),
            10,
            0,
        )?;
        assert_eq!(uncategorized.total_in_category, 2);
        assert_eq!(
            uncategorized
                .entries
                .iter()
                .map(|entry| entry.logical_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/null.bin", "/unknown.bin"]
        );

        let all_categories =
            list_entries_by_category(&case_path, Some(first_evidence_id), "", None, 100, 0)?;
        assert_eq!(all_categories.total_in_category, 8);
        assert_eq!(all_categories.entries.len(), 8);
        assert_eq!(
            list_entries_by_category(
                &case_path,
                Some(first_evidence_id),
                "Program Execution",
                None,
                10,
                0,
            )?
            .total_in_category,
            1
        );
        assert_eq!(
            list_entries_by_category(
                &case_path,
                Some(first_evidence_id),
                "Cloud and Web",
                None,
                10,
                0,
            )?
            .total_in_category,
            1
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(first_source);
        let _ = fs::remove_dir_all(second_source);
        Ok(())
    }

    #[test]
    fn evidence_process_indexes_folder_and_deep_searches_content() -> Result<()> {
        let case_path = unique_case_path("process-search");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-source");
        let nested = evidence_dir.join("Users").join("Examiner");
        fs::create_dir_all(&nested)?;
        fs::write(
            nested.join("history.txt"),
            b"Visited example.com with browser keyword evidence",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        assert_eq!(filesystem_entry_count(&case_path)?, 0);

        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");
        assert!(!processed.truncated);
        assert!(processed.entries_indexed >= 3);
        assert!(filesystem_entry_count(&case_path)? >= 3);

        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let history_entry = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/history.txt"))
            .expect("history entry should be listed");
        let entry_bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: history_entry.id,
                offset: 0,
                length: 7,
            },
        )?;
        assert_eq!(entry_bytes.bytes, b"Visited");

        let path_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "history.txt".to_string(),
                evidence_id: Some(evidence_id),
                include_content: false,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        assert!(path_hits.iter().any(|hit| hit.match_kind == "path"));

        let content_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "keyword".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let content_hit = content_hits
            .iter()
            .find(|hit| hit.match_kind == "content")
            .expect("content hit should be returned");
        assert_eq!(content_hit.evidence_id, evidence_id);
        assert!(content_hit.entry_id > 0);
        assert_eq!(content_hit.selection_length, Some("keyword".len() as i64));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn evidence_process_populates_content_head_for_folder_content_search() -> Result<()> {
        let case_path = unique_case_path("process-content-head");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-content-head-source");
        fs::create_dir_all(&evidence_dir)?;
        let content = b"stored deep search token in indexed bytes";
        fs::write(evidence_dir.join("note.txt"), content)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let conn = open_existing_case(&case_path)?;
        let stored: Vec<u8> = conn.query_row(
            "SELECT content_head
             FROM filesystem_entries
             WHERE evidence_id = ?1 AND logical_path LIKE '%/note.txt'",
            params![evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(stored, content);
        drop(conn);

        fs::remove_dir_all(&evidence_dir)?;
        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "deep search token".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let hit = hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/note.txt") && hit.match_kind == "content")
            .expect("content hit should come from stored content_head");
        assert_eq!(hit.selection_offset, Some(7));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn deep_search_scans_raw_byte_windows_in_large_and_unicode_files() -> Result<()> {
        let case_path = unique_case_path("process-search-bytes");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-bytes-source");
        fs::create_dir_all(&evidence_dir)?;

        let large_needle = b"VisibleNameInLargeBinary";
        // Within the indexed keyword-preview window (CONTENT_INDEX_BYTES); the
        // file itself is far larger, so this still exercises searching a big
        // file through the bounded preview.
        let large_offset = 2048;
        let mut large_bytes = vec![0_u8; 128 * 1024];
        large_bytes[large_offset..large_offset + large_needle.len()].copy_from_slice(large_needle);
        fs::write(evidence_dir.join("large.bin"), large_bytes)?;

        let mut utf16_bytes = vec![0xFF, 0xFE];
        for unit in "Visible UTF16 Secret".encode_utf16() {
            utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(evidence_dir.join("utf16.bin"), utf16_bytes)?;

        // UTF-16LE text at an ODD byte offset (13-byte ASCII prefix). On-disk strings have no
        // alignment guarantee; an even-step scan misses these (regression for the step_by(2) bug).
        let mut odd_utf16_bytes = b"BEGIN-MARKER ".to_vec();
        for unit in "classifiedsecret".encode_utf16() {
            odd_utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        odd_utf16_bytes.extend_from_slice(b" END-MARKER");
        fs::write(evidence_dir.join("odd-utf16.bin"), odd_utf16_bytes)?;
        fs::write(
            evidence_dir.join("signature.bin"),
            [0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let large_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "visiblenameinlargebinary".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let large_hit = large_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/large.bin"))
            .expect("large file should be searched through the capped byte window");
        assert_eq!(large_hit.match_kind, "content");
        assert_eq!(large_hit.selection_offset, Some(large_offset as i64));
        assert_eq!(large_hit.selection_length, Some(large_needle.len() as i64));

        let utf16_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "utf16 secret".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let utf16_hit = utf16_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/utf16.bin"))
            .expect("UTF-16LE text should be searchable from raw bytes");
        assert_eq!(utf16_hit.selection_offset, Some(18));
        assert_eq!(
            utf16_hit.selection_length,
            Some("utf16 secret".encode_utf16().count() as i64 * 2)
        );

        let odd_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "classifiedsecret".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let odd_hit = odd_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/odd-utf16.bin"))
            .expect("odd-offset UTF-16LE text must be found (no alignment assumption)");
        assert_eq!(odd_hit.selection_offset, Some(13));
        assert_eq!(
            odd_hit.selection_length,
            Some("classifiedsecret".encode_utf16().count() as i64 * 2)
        );

        let hex_hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "hex:DE AD BE EF".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        let hex_hit = hex_hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/signature.bin"))
            .expect("explicit hex byte query should match exact bytes");
        assert_eq!(hex_hit.selection_offset, Some(1));
        assert_eq!(hex_hit.selection_length, Some(4));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_content_scans_beyond_first_thousand_file_candidates() -> Result<()> {
        let case_path = unique_case_path("process-search-candidate-limit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-search-candidate-limit-source");
        fs::create_dir_all(&evidence_dir)?;

        for index in 0..1499 {
            fs::write(
                evidence_dir.join(format!("aaa_{index:04}.txt")),
                b"small filler file",
            )?;
        }
        fs::write(
            evidence_dir.join("zzz_target.txt"),
            b"needle-beyond-old-cap",
        )?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 2_000,
            },
        )?;
        assert_eq!(processed.status, "completed");

        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "needle-beyond-old-cap".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 50,
                max_file_bytes: 1024,
            },
        )?;
        let target_hit = hits
            .iter()
            .find(|hit| hit.logical_path.ends_with("/zzz_target.txt"))
            .expect("target sorted beyond the old 1000-candidate cap should be content-scanned");
        assert_eq!(target_hit.match_kind, "content");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_pages_cover_every_match_without_a_result_ceiling() -> Result<()> {
        let case_path = unique_case_path("deep-search-pages");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("deep-search-pages-source");
        fs::create_dir_all(&evidence_dir)?;
        for index in 0..7 {
            fs::write(
                evidence_dir.join(format!("paged-match-{index}.txt")),
                b"bounded response",
            )?;
        }
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let options = DeepSearchOptions {
            category: None,
            file_types: None,
            query: "paged-match".to_string(),
            evidence_id: Some(evidence_id),
            include_content: false,
            max_results: 2,
            max_file_bytes: 4096,
        };
        let mut cursor = None;
        let mut paths = Vec::new();
        let mut page_lengths = Vec::new();
        loop {
            let page = deep_search_page(&case_path, options.clone(), cursor, 2)?;
            assert_eq!(page.coverage.generic_file_content_bytes_per_file, 4096);
            assert!(!page.coverage.raw_evidence_bytes_included);
            page_lengths.push(page.results.len());
            paths.extend(page.results.into_iter().map(|hit| hit.logical_path));
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = Some(page.next_cursor.context("incomplete page needs a cursor")?);
        }
        assert_eq!(page_lengths, vec![2, 2, 2, 1]);
        assert_eq!(paths.len(), 7);
        assert_eq!(paths.iter().collect::<HashSet<_>>().len(), 7);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn deep_search_pages_apply_cross_phase_precedence_and_unicode_segment_overlap() -> Result<()> {
        let case_path = unique_case_path("deep-search-phase-precedence");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("deep-search-phase-precedence-source");
        fs::create_dir_all(&evidence_dir)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json, content_head)
             VALUES (?1, ?2, '/needle-name.txt', 'needle-name.txt', 'file', '{}', ?3)",
            params![
                case_id,
                evidence_id,
                b"needle in generic content".as_slice()
            ],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json, content_head)
             VALUES (?1, ?2, '/plain.bin', 'plain.bin', 'file', '{}', ?3)",
            params![
                case_id,
                evidence_id,
                b"needle in generic content".as_slice()
            ],
        )?;
        let parsed_entry_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO filesystem_entry_text_segments(
                 entry_id, parser_name, segment_index, part_name, content, content_encoding)
             VALUES (?1, 'test-parser', 0, 'body', ?2, 'utf-8')",
            params![parsed_entry_id, b"needle in parsed content".as_slice()],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json)
             VALUES (?1, ?2, '/unicode.bin', 'unicode.bin', 'file', '{}')",
            params![case_id, evidence_id],
        )?;
        let unicode_entry_id = conn.last_insert_rowid();
        for (segment_index, content) in [
            (0_i64, b"prefix caf\xC3".as_slice()),
            (1_i64, b"\xA9-marker suffix".as_slice()),
        ] {
            conn.execute(
                "INSERT INTO filesystem_entry_text_segments(
                     entry_id, parser_name, segment_index, part_name, content, content_encoding)
                 VALUES (?1, 'test-parser', ?2, 'body', ?3, 'utf-8')",
                params![unicode_entry_id, segment_index, content],
            )?;
        }
        drop(conn);

        let options = DeepSearchOptions {
            query: "needle".to_string(),
            evidence_id: Some(evidence_id),
            include_content: true,
            max_results: 1,
            max_file_bytes: 4096,
            category: None,
            file_types: None,
        };
        let mut cursor = None;
        let mut hits = Vec::new();
        loop {
            let page = deep_search_page(&case_path, options.clone(), cursor, 1)?;
            hits.extend(page.results);
            if page.complete {
                break;
            }
            cursor = Some(page.next_cursor.context("incomplete page needs a cursor")?);
        }
        assert_eq!(hits.len(), 2, "one row per matching entry is required");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.entry_id)
                .collect::<HashSet<_>>()
                .len(),
            2
        );
        assert!(hits
            .iter()
            .any(|hit| { hit.logical_path == "/needle-name.txt" && hit.match_kind == "path" }));
        assert!(hits
            .iter()
            .any(|hit| { hit.logical_path == "/plain.bin" && hit.match_kind == "parsed_content" }));

        let unicode = deep_search_page(
            &case_path,
            DeepSearchOptions {
                query: "café-marker".to_string(),
                evidence_id: Some(evidence_id),
                include_content: true,
                max_results: 10,
                max_file_bytes: 4096,
                category: None,
                file_types: None,
            },
            None,
            10,
        )?;
        assert!(unicode.complete);
        assert_eq!(unicode.results.len(), 1);
        assert_eq!(unicode.results[0].entry_id, unicode_entry_id);
        assert_eq!(unicode.results[0].match_kind, "parsed_content");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn recover_filesystem_entry_exports_indexed_file_bytes() -> Result<()> {
        let case_path = unique_case_path("recover-entry");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("recover-entry-source");
        let nested = evidence_dir.join("Users").join("Examiner");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("note.txt"), b"Recovered evidence bytes")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let note = entries
            .iter()
            .find(|entry| entry.logical_path.ends_with("/note.txt"))
            .expect("note.txt should be indexed");
        let output_dir = unique_temp_dir("recover-entry-output");
        let output_path = output_dir.join("note-recovered.txt");

        let recovered = recover_filesystem_entry(
            &case_path,
            RecoverEntryOptions {
                entry_id: note.id,
                output_path: output_path.clone(),
            },
        )?;

        assert_eq!(recovered.evidence_id, evidence_id);
        assert_eq!(
            recovered.bytes_written,
            b"Recovered evidence bytes".len() as u64
        );
        assert_eq!(
            recovered.total_size,
            b"Recovered evidence bytes".len() as u64
        );
        assert_eq!(recovered.status, "completed");
        assert_eq!(fs::read(&output_path)?, b"Recovered evidence bytes");

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(output_dir);
        Ok(())
    }

    #[test]
    fn disk_image_file_entries_return_raw_container_bytes() -> Result<()> {
        let case_path = unique_case_path("folder-dd-image");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("folder-dd-image-source");
        fs::write(evidence_dir.join("guest.dd"), b"raw container bytes")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let entry = entries
            .iter()
            .find(|entry| entry.logical_path == "/guest.dd")
            .expect("folder .dd entry should be indexed");
        let bytes = read_filesystem_entry_bytes(
            &case_path,
            ReadEntryBytesOptions {
                entry_id: entry.id,
                offset: 4,
                length: 9,
            },
        )?;
        assert_eq!(bytes.bytes, b"container");
        assert_eq!(bytes.total_size, b"raw container bytes".len() as u64);
        assert!(!bytes.eof);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn browser_record_spool_streams_multiple_batches_and_preserves_canonical_values() -> Result<()>
    {
        let mut spool = BrowserRecordSpool::new(Path::new("History"))?;
        let mut global_index = 0_usize;
        for (kind, batch_len) in [
            (BrowserRecordKind::Visit, 513_usize),
            (BrowserRecordKind::Cookie, 512_usize),
            (BrowserRecordKind::Visit, 512_usize),
        ] {
            for _ in 0..batch_len {
                let logical_path = format!(
                    "/Browser Activities/Visits/example.test/raw value {global_index}?q=%2F&unicode=é"
                );
                let canonical_database_name =
                    format!("History::canonical/raw value {global_index}?q=%2F&unicode=é");
                spool.push(
                    kind,
                    BrowserActivityRecord {
                        logical_path,
                        display_name: format!("Record {global_index}"),
                        metadata_json: serde_json::json!({
                            "canonical_database_name": canonical_database_name,
                        })
                        .to_string(),
                    },
                )?;
                global_index += 1;
            }
        }
        spool.seal()?;

        assert_eq!(spool.counts.visits, 1_025);
        assert_eq!(spool.counts.cookies, 512);
        assert_eq!(spool.counts.total(), 1_537);
        let mut seen = 0_usize;
        spool.for_each_record(|record| {
            assert_eq!(
                record.logical_path,
                format!("/Browser Activities/Visits/example.test/raw value {seen}?q=%2F&unicode=é")
            );
            let metadata: serde_json::Value = serde_json::from_str(&record.metadata_json)?;
            let expected_canonical = format!("History::canonical/raw value {seen}?q=%2F&unicode=é");
            assert_eq!(
                metadata["canonical_database_name"].as_str(),
                Some(expected_canonical.as_str())
            );
            seen += 1;
            Ok(())
        })?;
        assert_eq!(seen, 1_537);
        Ok(())
    }

    #[test]
    fn browser_record_emitter_surfaces_sink_error_without_retaining_later_records() {
        let mut successful = 0_usize;
        let mut attempts = 0_usize;
        let mut sink = |_record: BrowserActivityRecord| -> Result<()> {
            attempts += 1;
            if successful == 3 {
                return Err(anyhow!("synthetic browser spool failure"));
            }
            successful += 1;
            Ok(())
        };
        let mut emitter = BrowserRecordEmitter::new(&mut sink);
        for index in 0..10 {
            emitter.push(BrowserActivityRecord {
                logical_path: format!("/record/{index}"),
                display_name: index.to_string(),
                metadata_json: "{}".to_string(),
            });
        }
        let error = emitter.finish().expect_err("sink error must be returned");
        assert!(error
            .to_string()
            .contains("synthetic browser spool failure"));
        assert_eq!(successful, 3);
        assert_eq!(attempts, 4);
    }

    #[test]
    fn browser_spool_paths_are_exclusively_reserved() -> Result<()> {
        let first = reserve_unique_browser_spool_path("kdft-spool-test", Path::new("History"))?;
        let second = reserve_unique_browser_spool_path("kdft-spool-test", Path::new("History"))?;
        assert_ne!(first, second);
        assert!(first.is_file());
        assert!(second.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&first)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&second)?.permissions().mode() & 0o777, 0o600);
        }
        fs::remove_file(first)?;
        fs::remove_file(second)?;
        Ok(())
    }

    #[test]
    fn browser_import_diagnostics_keep_bounded_samples_and_exact_total() -> Result<()> {
        let mut diagnostics = BrowserImportDiagnostics::default();
        for index in 0..(BROWSER_IMPORT_ERROR_SAMPLE_LIMIT + 17) {
            diagnostics.record(format!("reader failure {index}"));
        }
        assert_eq!(
            diagnostics.total,
            (BROWSER_IMPORT_ERROR_SAMPLE_LIMIT + 17) as u64
        );
        assert_eq!(diagnostics.samples.len(), BROWSER_IMPORT_ERROR_SAMPLE_LIMIT);
        assert_eq!(diagnostics.samples[0], "reader failure 0");
        assert_eq!(
            diagnostics.samples[BROWSER_IMPORT_ERROR_SAMPLE_LIMIT - 1],
            format!("reader failure {}", BROWSER_IMPORT_ERROR_SAMPLE_LIMIT - 1)
        );

        let mut spool = BrowserRecordSpool::new(Path::new("diagnostic-History"))?;
        spool.seal()?;
        let mut import_data = BrowserHistoryImportData {
            family: BrowserFamily::Chromium,
            source_path: "canonical/source/profile".to_string(),
            primary_db_path: PathBuf::from("History"),
            default_display_name: "Chromium History".to_string(),
            parameters_json: serde_json::json!({
                "parse_errors": ["existing failure"],
                "parse_error_count": 1,
            })
            .to_string(),
            records: spool,
            total_visits: 0,
            examiner_artifact_limit_reached: false,
            limited_artifact_kinds: Vec::new(),
            parse_errors: vec!["existing failure".to_string()],
            parse_error_count: 1,
        };
        import_data.add_diagnostics(diagnostics)?;
        assert_eq!(import_data.parse_error_count, 50);
        assert_eq!(
            import_data.parse_errors.len(),
            BROWSER_IMPORT_ERROR_SAMPLE_LIMIT
        );
        let parameters: serde_json::Value = serde_json::from_str(&import_data.parameters_json)?;
        assert_eq!(parameters["parse_error_count"].as_u64(), Some(50));
        assert_eq!(parameters["parse_error_samples_omitted"].as_u64(), Some(18));
        Ok(())
    }

    #[test]
    fn ext_browser_staging_filter_accepts_only_exact_parser_inputs() {
        for name in [
            "History",
            "History-wal",
            "History-journal",
            "Bookmarks",
            "Web Data-shm",
            "places.sqlite-wal",
            "downloads.sqlite-shm",
            "logins.json",
            "History.db-shm",
            "places.sqlite-journal",
        ] {
            assert!(is_ext_browser_top_level_artifact(name), "{name}");
        }
        for name in [
            "Cache",
            "f_000001",
            "History Backup",
            "history",
            "Cookies.tmp",
            "Local Storage",
        ] {
            assert!(!is_ext_browser_top_level_artifact(name), "{name}");
        }
        for name in ["Cookies", "Cookies-wal", "Cookies-shm", "Cookies-journal"] {
            assert!(is_ext_browser_network_artifact(name), "{name}");
        }
        for name in ["History", "Network Persistent State", "Cookies.tmp"] {
            assert!(!is_ext_browser_network_artifact(name), "{name}");
        }
    }

    #[test]
    fn staged_history_filename_requires_a_browser_schema() -> Result<()> {
        let staging = unique_temp_dir("staged-history-schema");
        fs::write(
            staging.join("History"),
            b"ordinary application history text",
        )?;
        assert_eq!(detect_staged_browser_family(&staging)?, None);
        fs::remove_file(staging.join("History"))?;
        create_empty_chromium_history_core(&staging.join("History"))?;
        assert_eq!(
            detect_staged_browser_family(&staging)?,
            Some(BrowserFamily::Chromium)
        );
        let _ = fs::remove_dir_all(staging);
        Ok(())
    }

    #[test]
    fn ext_browser_profile_persistence_rolls_back_partial_replacement_on_sink_error() -> Result<()>
    {
        let case_path = unique_case_path("ext-browser-savepoint");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("ext-browser-savepoint-source");
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_jobs(
                case_id, evidence_id, job_type, status, parameters_json, started_at
             ) VALUES (?1, ?2, 'filesystem_index', 'running', '{}',
                       strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![case_id, evidence_id],
        )?;
        let job_id = conn.last_insert_rowid();
        let source_profile = "/home/alice/.config/chromium/Default";
        let derivation_key = browser_profile_derivation_key(source_profile, Some(0));
        let prior_path = "/Browser Activities/Profiles/prior-derived.record";
        upsert_filesystem_entry(
            &conn,
            case_id,
            evidence_id,
            prior_path,
            "Prior derived record",
            "record",
            None,
            &serde_json::json!({
                "artifact_kind": "prior_browser_record",
                "browser_derivation_key": derivation_key,
            })
            .to_string(),
            job_id,
        )?;

        let mut records = BrowserRecordSpool::new(Path::new("History"))?;
        records.push(
            BrowserRecordKind::Visit,
            BrowserActivityRecord {
                logical_path: "/Browser Activities/Visits/valid.record".to_string(),
                display_name: "Valid before failure".to_string(),
                metadata_json: serde_json::json!({
                    "artifact_kind": "browser_visit",
                    "source_artifact": "History",
                })
                .to_string(),
            },
        )?;
        records.push(
            BrowserRecordKind::Visit,
            BrowserActivityRecord {
                logical_path: "/Browser Activities/Visits/invalid.record".to_string(),
                display_name: "Invalid metadata".to_string(),
                metadata_json: "not valid JSON".to_string(),
            },
        )?;
        records.seal()?;
        let import_data = BrowserHistoryImportData {
            family: BrowserFamily::Chromium,
            source_path: source_profile.to_string(),
            primary_db_path: PathBuf::from("History"),
            default_display_name: "Chromium History".to_string(),
            parameters_json: "{}".to_string(),
            records,
            total_visits: 2,
            examiner_artifact_limit_reached: false,
            limited_artifact_kinds: Vec::new(),
            parse_errors: Vec::new(),
            parse_error_count: 0,
        };
        let error = persist_auto_browser_profile_import(
            &conn,
            case_id,
            evidence_id,
            job_id,
            source_profile,
            Some(0),
            &evidence_dir,
            &import_data,
        )
        .expect_err("invalid spooled metadata must fail profile persistence");
        assert!(error.to_string().contains("parsing browser metadata"));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM filesystem_entries
                 WHERE case_id = ?1 AND evidence_id = ?2 AND logical_path = ?3",
                params![case_id, evidence_id, prior_path],
                |row| row.get::<_, i64>(0),
            )?,
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM filesystem_entries
                 WHERE case_id = ?1 AND evidence_id = ?2
                   AND json_extract(metadata_json, '$.artifact_kind') = 'browser_visit'",
                params![case_id, evidence_id],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );

        drop(conn);
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn chromium_bookmarks_stream_large_nested_array_without_result_accumulation() -> Result<()> {
        const BOOKMARKS: usize = 1_537;
        let profile_dir = unique_temp_dir("chromium-bookmarks-stream");
        let bookmarks_path = profile_dir.join("Bookmarks");
        let mut output = fs::File::create(&bookmarks_path)?;
        output.write_all(br#"{"roots":{"bookmark_bar":{"children":["#)?;
        for index in 0..BOOKMARKS {
            if index > 0 {
                output.write_all(b",")?;
            }
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({
                    "type": "url",
                    "name": format!("Bookmark {index}"),
                    "url": format!("https://example.test/bookmark/{index}"),
                    "guid": format!("guid-{index}"),
                    "date_added": (13_300_000_000_000_000_i64 + index as i64).to_string(),
                }),
            )?;
        }
        output.write_all(br#"],"name":"Bookmarks Bar","type":"folder"}}}"#)?;
        output.flush()?;
        drop(output);

        let mut seen = 0_usize;
        let emitted = stream_chromium_bookmark_records(&bookmarks_path, &mut |record| {
            let metadata: serde_json::Value = serde_json::from_str(&record.metadata_json)?;
            if seen == 0 || seen == BOOKMARKS - 1 {
                let expected_name = format!("Bookmark {seen}");
                let expected_url = format!("https://example.test/bookmark/{seen}");
                assert_eq!(metadata["name"].as_str(), Some(expected_name.as_str()));
                assert_eq!(metadata["url"].as_str(), Some(expected_url.as_str()));
                assert_eq!(metadata["folder"].as_str(), Some("Bookmarks Bar"));
            }
            seen += 1;
            Ok(())
        })?;
        assert_eq!(emitted, BOOKMARKS);
        assert_eq!(seen, BOOKMARKS);

        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn streamed_browser_json_ignores_unexpected_optional_scalar_types() -> Result<()> {
        let profile_dir = unique_temp_dir("browser-json-mixed-types");
        let bookmarks_path = profile_dir.join("Bookmarks");
        fs::write(
            &bookmarks_path,
            serde_json::json!({
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "children": [{
                            "type": "url",
                            "name": 42,
                            "url": "https://mixed.example/bookmark",
                            "guid": false,
                            "date_added": {"unexpected": true}
                        }]
                    }
                }
            })
            .to_string(),
        )?;
        let mut bookmark_records = Vec::new();
        assert_eq!(
            stream_chromium_bookmark_records(&bookmarks_path, &mut |record| {
                bookmark_records.push(record.metadata_json);
                Ok(())
            })?,
            1
        );
        let bookmark: serde_json::Value = serde_json::from_str(&bookmark_records[0])?;
        assert_eq!(
            bookmark["url"].as_str(),
            Some("https://mixed.example/bookmark")
        );
        assert_eq!(bookmark["name"].as_str(), Some("Bookmark"));
        assert!(bookmark["guid"].is_null());
        assert!(bookmark["date_added_chrome"].is_null());

        let logins_path = profile_dir.join("logins.json");
        fs::write(
            &logins_path,
            serde_json::json!({
                "logins": [{
                    "hostname": {"unexpected": true},
                    "httpRealm": 7,
                    "timeCreated": false,
                    "timesUsed": "3"
                }]
            })
            .to_string(),
        )?;
        let mut login_records = Vec::new();
        assert_eq!(
            stream_firefox_login_records(&logins_path, usize::MAX, &mut |record| {
                login_records.push(record.metadata_json);
                Ok(())
            })?,
            1
        );
        let login: serde_json::Value = serde_json::from_str(&login_records[0])?;
        assert!(login["hostname"].is_null());
        assert!(login["http_realm"].is_null());
        assert!(login["time_created_ms"].is_null());
        assert_eq!(login["times_used"].as_i64(), Some(3));

        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_logins_stream_large_array_through_disk_sort_with_exact_limit() -> Result<()> {
        const LOGINS: usize = 1_537;
        const POSITIVE_LIMIT: usize = 257;
        let profile_dir = unique_temp_dir("firefox-logins-stream");
        let logins_path = profile_dir.join("logins.json");
        let mut output = fs::File::create(&logins_path)?;
        output.write_all(br#"{"version":3,"logins":["#)?;
        for index in 0..LOGINS {
            if index > 0 {
                output.write_all(b",")?;
            }
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({
                    "hostname": format!("https://host-{index}.example.test"),
                    "httpRealm": format!("realm-{index}"),
                    "timeCreated": 1_700_000_000_000_i64 + index as i64,
                    "timeLastUsed": 1_800_000_000_000_i64 + index as i64,
                    "timePasswordChanged": 1_750_000_000_000_i64 + index as i64,
                    "timesUsed": index,
                    "encryptedUsername": format!("ENC-USER-{index}"),
                    "encryptedPassword": format!("ENC-PASSWORD-{index}"),
                }),
            )?;
        }
        output.write_all(b"]}")?;
        output.flush()?;
        drop(output);

        let mut seen = 0_usize;
        let emitted = stream_firefox_login_records(&logins_path, usize::MAX, &mut |record| {
            let metadata: serde_json::Value = serde_json::from_str(&record.metadata_json)?;
            assert_eq!(
                metadata["password_note"].as_str(),
                Some("encrypted username/password retained as ciphertext; not decrypted")
            );
            if seen == 0 {
                let expected_hostname = format!("https://host-{}.example.test", LOGINS - 1);
                assert_eq!(
                    metadata["hostname"].as_str(),
                    Some(expected_hostname.as_str())
                );
                let expected_username = format!("ENC-USER-{}", LOGINS - 1);
                let expected_password = format!("ENC-PASSWORD-{}", LOGINS - 1);
                assert_eq!(
                    metadata["username_ciphertext"].as_str(),
                    Some(expected_username.as_str())
                );
                assert_eq!(
                    metadata["password_ciphertext"].as_str(),
                    Some(expected_password.as_str())
                );
            }
            if seen == LOGINS - 1 {
                assert_eq!(
                    metadata["hostname"].as_str(),
                    Some("https://host-0.example.test")
                );
            }
            seen += 1;
            Ok(())
        })?;
        assert_eq!(emitted, LOGINS);
        assert_eq!(seen, LOGINS);

        let mut limited_seen = 0_usize;
        let limited = stream_firefox_login_records(&logins_path, POSITIVE_LIMIT, &mut |_record| {
            limited_seen += 1;
            Ok(())
        })?;
        assert_eq!(limited, POSITIVE_LIMIT);
        assert_eq!(limited_seen, POSITIVE_LIMIT);

        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn positive_browser_limit_discloses_non_visit_omissions_exactly() -> Result<()> {
        const LIMIT: usize = 2;
        let case_path = unique_case_path("chromium-cookie-only-limit");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-cookie-only-limit-source");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        fs::create_dir_all(profile_dir.join("Network"))?;
        let cookies = Connection::open(profile_dir.join("Network").join("Cookies"))?;
        cookies.execute_batch(
            "CREATE TABLE cookies(
                host_key TEXT, name TEXT, path TEXT, creation_utc INTEGER,
                expires_utc INTEGER, last_access_utc INTEGER,
                is_secure INTEGER, is_httponly INTEGER
             );
             INSERT INTO cookies VALUES
                ('a.example', 'one', '/', 30, 0, 30, 1, 1),
                ('b.example', 'two', '/', 20, 0, 20, 0, 1);",
        )?;
        drop(cookies);

        let exact = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: LIMIT,
                evidence_name: None,
            },
        )?;
        assert_eq!(exact.entries_indexed, LIMIT);
        assert!(!exact.visit_limit_reached);
        assert!(!exact.artifact_limit_reached);
        assert!(!exact.truncated);
        assert_eq!(exact.status, "completed");

        let cookies = Connection::open(profile_dir.join("Network").join("Cookies"))?;
        cookies.execute(
            "INSERT INTO cookies VALUES
             ('c.example', 'three', '/', 10, 0, 10, 0, 0)",
            [],
        )?;
        drop(cookies);
        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: LIMIT,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 0);
        assert!(!imported.visit_limit_reached);
        assert!(imported.artifact_limit_reached);
        assert_eq!(imported.limited_artifact_kinds, vec!["cookies"]);
        assert_eq!(imported.entries_indexed, LIMIT);
        assert!(imported.truncated);
        assert_eq!(imported.status, "truncated");
        let conn = open_existing_case(&case_path)?;
        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![imported.job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        assert_eq!(parameters["artifact_limit_reached"].as_bool(), Some(true));
        assert_eq!(
            parameters["limited_artifact_kinds"],
            serde_json::json!(["cookies"])
        );

        drop(conn);
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn missing_required_firefox_and_safari_schemas_never_report_complete() -> Result<()> {
        for (label, file_name, family, expected) in [
            (
                "firefox-missing-core",
                "places.sqlite",
                BrowserFamily::Firefox,
                "Firefox history schema is missing required table",
            ),
            (
                "safari-missing-core",
                "History.db",
                BrowserFamily::Safari,
                "Safari history schema is missing required table",
            ),
        ] {
            let case_path = unique_case_path(label);
            create_test_case(&case_path)?;
            let profile_dir = unique_temp_dir(label);
            let database_path = profile_dir.join(file_name);
            drop(Connection::open(&database_path)?);
            let imported = import_browser_history_for_family(
                &case_path,
                family,
                ImportBrowserHistoryOptions {
                    history_path: database_path,
                    max_visits: 0,
                    evidence_name: None,
                },
            )?;
            assert!(imported.truncated, "{label}");
            assert_eq!(imported.status, "truncated", "{label}");
            assert!(imported.parse_error_count > 0, "{label}");
            assert!(
                imported
                    .parse_errors
                    .iter()
                    .any(|error| error.contains(expected)),
                "{label}: {:?}",
                imported.parse_errors
            );

            cleanup_case_path(&case_path);
            let _ = fs::remove_dir_all(profile_dir);
        }
        Ok(())
    }

    #[test]
    fn chromium_preferences_bound_is_exact_and_marks_import_truncated() -> Result<()> {
        const TEST_BOUND: u64 = 64;
        let case_path = unique_case_path("chromium-preferences-bound");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-preferences-bound-source");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        let preferences_path = profile_dir.join("Preferences");
        fs::write(
            &preferences_path,
            serde_json::json!({
                "profile": {"name": "A".repeat(256)},
                "extensions": {"settings": {"large": "B".repeat(256)}}
            })
            .to_string(),
        )?;
        let total_bytes = fs::metadata(&preferences_path)?.len();
        assert!(total_bytes > TEST_BOUND);

        let import_data = collect_chromium_history_import_with_protections(
            &profile_dir,
            usize::MAX,
            1_024,
            TEST_BOUND,
        )?;
        assert_eq!(import_data.parse_error_count, 1);
        assert!(import_data.parse_errors.iter().any(|error| {
            error.contains(CHROMIUM_PREFERENCES_MAX_BYTES_ENV)
                && error.contains(&format!("{} total bytes", total_bytes))
                && error.contains(&format!(
                    "{} bytes were not parsed",
                    total_bytes - TEST_BOUND
                ))
        }));
        let imported = persist_browser_history_import(
            &case_path,
            Some("Bounded Preferences".to_string()),
            import_data,
        )?;
        assert!(imported.truncated);
        assert!(!imported.visit_limit_reached);
        assert_eq!(imported.status, "truncated");
        assert_eq!(imported.parse_error_count, 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_download_url_chain_bound_keeps_endpoints_and_exact_partial_status() -> Result<()> {
        let case_path = unique_case_path("chromium-download-chain-bound");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-download-chain-bound-source");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        Connection::open(&history_path)?.execute_batch(
            "CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT);
             CREATE TABLE downloads_url_chains(
                 id INTEGER, chain_index INTEGER, url TEXT
             );
             INSERT INTO downloads(id, current_path)
             VALUES (7, 'C:\\Downloads\\bounded.bin');
             INSERT INTO downloads_url_chains(id, chain_index, url) VALUES
                 (7, 0, 'https://chain.example/0'),
                 (7, 1, 'https://chain.example/1'),
                 (7, 2, 'https://chain.example/2'),
                 (7, 3, 'https://chain.example/3'),
                 (7, 4, 'https://chain.example/4');",
        )?;

        let import_data = collect_chromium_history_import_with_protections(
            &profile_dir,
            usize::MAX,
            2,
            DEFAULT_CHROMIUM_PREFERENCES_MAX_BYTES,
        )?;
        assert_eq!(import_data.parse_error_count, 1);
        assert!(import_data.parse_errors.iter().any(|error| {
            error.contains("retained 2 of 5 URLs") && error.contains("omitted 3")
        }));
        let imported = persist_browser_history_import(
            &case_path,
            Some("Bounded URL Chain".to_string()),
            import_data,
        )?;
        assert!(imported.truncated);
        assert!(!imported.visit_limit_reached);
        assert_eq!(imported.parse_error_count, 1);
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let download = entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"] == "browser_download")
            .context("bounded download record")?;
        assert_eq!(
            download.metadata_json["url_chain"],
            serde_json::json!(["https://chain.example/0", "https://chain.example/1"])
        );
        assert_eq!(download.metadata_json["url_chain_total"].as_u64(), Some(5));
        assert_eq!(
            download.metadata_json["url_chain_omitted"].as_u64(),
            Some(3)
        );
        assert_eq!(
            download.metadata_json["url_chain_complete"].as_bool(),
            Some(false)
        );
        assert_eq!(
            download.metadata_json["original_url"].as_str(),
            Some("https://chain.example/0")
        );
        assert_eq!(
            download.metadata_json["download_url"].as_str(),
            Some("https://chain.example/4")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_unlimited_import_streams_all_rows_and_positive_limit_is_exact() -> Result<()> {
        const ROWS: i64 = 1_200;
        const POSITIVE_LIMIT: usize = 257;

        let case_path = unique_case_path("chromium-streaming-volume");
        create_test_case(&case_path)?;
        let history_dir = unique_temp_dir("chromium-streaming-volume-source");
        let history_path = history_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        let mut history = Connection::open(&history_path)?;
        let tx = history.transaction()?;
        {
            let mut insert_url = tx.prepare(
                "INSERT INTO urls(
                    id, url, title, visit_count, typed_count, last_visit_time, hidden
                 ) VALUES (?1, ?2, ?3, 1, 0, ?4, 0)",
            )?;
            let mut insert_visit = tx.prepare(
                "INSERT INTO visits(id, url, visit_time, transition)
                 VALUES (?1, ?1, ?2, 1)",
            )?;
            for id in 1..=ROWS {
                let timestamp = 13_300_000_000_000_000_i64 + id;
                insert_url.execute(params![
                    id,
                    format!("https://example.test/stream/{id}"),
                    format!("Streaming row {id}"),
                    timestamp,
                ])?;
                insert_visit.execute(params![id, timestamp])?;
            }
        }
        tx.commit()?;
        drop(history);

        let unlimited = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 0,
                evidence_name: Some("Streaming Chromium History".to_string()),
            },
        )?;
        assert_eq!(unlimited.visits_indexed, ROWS as usize);
        assert_eq!(unlimited.entries_indexed, (ROWS as usize) * 2);
        assert!(!unlimited.visit_limit_reached);
        assert!(!unlimited.truncated);
        assert_eq!(unlimited.status, "completed");
        assert_eq!(unlimited.parse_error_count, 0);

        let limited = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: POSITIVE_LIMIT,
                evidence_name: Some("Streaming Chromium History".to_string()),
            },
        )?;
        assert_eq!(limited.evidence_id, unlimited.evidence_id);
        assert_eq!(limited.visits_indexed, POSITIVE_LIMIT);
        assert_eq!(limited.entries_indexed, POSITIVE_LIMIT * 2);
        assert!(limited.visit_limit_reached);
        assert!(limited.truncated);
        assert_eq!(limited.status, "truncated");
        assert_eq!(limited.parse_error_count, 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(history_dir);
        Ok(())
    }

    #[test]
    fn chromium_history_import_creates_searchable_record_entries() -> Result<()> {
        let case_path = unique_case_path("history-import");
        create_test_case(&case_path)?;
        let history_dir = unique_temp_dir("history-import-source");
        let history_path = history_dir.join("History");
        create_test_chromium_history(&history_path)?;

        let imported = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 0,
                evidence_name: Some("Chrome Default History".to_string()),
            },
        )?;
        assert_eq!(imported.visits_indexed, 2);
        assert_eq!(imported.bookmarks_indexed, 2);
        assert_eq!(imported.preferences_indexed, 6);
        // 2 visits + 2 bookmarks + 6 preferences + 2 unique URLs + 1 search + 1 download
        assert_eq!(imported.entries_indexed, 14);
        assert!(!imported.truncated);
        assert_eq!(imported.status, "completed");

        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "browser_history");
        assert!(evidence[0].indexed_at.is_some());

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(entries.len(), 14);
        assert!(entries.iter().all(|entry| entry.entry_kind == "record"));

        // DFIR browser categories: URLs, Searches, and Downloads rows with Web Activity mains.
        let url_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/URLs/example.com/")
            })
            .expect("unique URL record should be imported");
        assert_eq!(
            url_entry.metadata_json["category_main"].as_str(),
            Some("Web Activity")
        );
        assert_eq!(
            url_entry.metadata_json["category_sub"].as_str(),
            Some("URLs")
        );
        let url_event_time = url_entry.metadata_json["last_visit_time_utc"]
            .as_str()
            .expect("URL record should carry a last visit time");
        assert!(url_entry.metadata_json["created_utc"].is_null());
        assert!(url_entry.metadata_json["accessed_utc"].is_null());
        assert!(url_entry.metadata_json["modified_utc"].is_null());
        assert_eq!(
            url_entry.metadata_json["source_file_time_basis"].as_str(),
            Some("local_source_filesystem")
        );
        let url_source_modified = url_entry.metadata_json["source_file_modified_utc"]
            .as_str()
            .expect("URL record should retain source file modified time");
        assert_ne!(url_source_modified, url_event_time);
        let search_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/Searches/")
            })
            .expect("search term record should be imported");
        assert_eq!(
            search_entry.metadata_json["search_term"].as_str(),
            Some("keyword")
        );
        assert_eq!(
            search_entry.metadata_json["category_sub"].as_str(),
            Some("Searches")
        );
        let download_entry = entries
            .iter()
            .find(|entry| {
                entry
                    .logical_path
                    .starts_with("/Browser Activities/Downloads/")
            })
            .expect("download record should be imported");
        assert_eq!(
            download_entry.metadata_json["file_name"].as_str(),
            Some("tool.zip")
        );
        assert_eq!(
            download_entry.metadata_json["category_sub"].as_str(),
            Some("Downloads")
        );
        let target = entries
            .iter()
            .find(|entry| {
                entry.name == "Example Page"
                    && entry
                        .logical_path
                        .starts_with("/Browser Activities/Visits/example.com/")
            })
            .expect("example history visit entry should be imported");
        assert_eq!(
            target.metadata_json["url"].as_str(),
            Some("https://example.com/path?q=keyword")
        );
        assert_eq!(
            target.metadata_json["transition_type"].as_str(),
            Some("typed")
        );
        assert_eq!(
            target.metadata_json["source_artifact"].as_str(),
            Some("History")
        );
        assert!(target.metadata_json["source_artifact_path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("History"));
        assert!(target.metadata_json["source_file_modified_utc"].is_string());

        let hits = deep_search(
            &case_path,
            DeepSearchOptions {
                category: None,
                file_types: None,
                query: "example.com/path".to_string(),
                evidence_id: Some(imported.evidence_id),
                include_content: false,
                max_results: 10,
                max_file_bytes: 64 * 1024,
            },
        )?;
        assert!(hits.iter().any(|hit| hit.entry_id == target.id));
        assert!(entries.iter().any(|entry| entry
            .logical_path
            .contains("/Browser Activities/Bookmarks/")));
        assert!(entries.iter().any(|entry| entry
            .logical_path
            .contains("/Browser Activities/Preferences/")));
        assert!(entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("browser_bookmark")
                && entry.metadata_json["url"].as_str() == Some("https://example.com/bookmark")
        }));

        let truncated = import_chromium_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 1,
                evidence_name: Some("Chrome Default History".to_string()),
            },
        )?;
        assert_eq!(truncated.evidence_id, imported.evidence_id);
        assert_eq!(truncated.visits_indexed, 1);
        assert_eq!(truncated.bookmarks_indexed, 2);
        assert_eq!(truncated.preferences_indexed, 6);
        // 1 visit + 2 bookmarks + 6 preferences + 1 URL + 1 search + 1 download (max_visits = 1)
        assert_eq!(truncated.entries_indexed, 12);
        assert!(truncated.truncated);
        assert_eq!(truncated.status, "truncated");
        assert_eq!(
            list_filesystem_entries(&case_path, Some(imported.evidence_id))?.len(),
            12
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(history_dir);
        Ok(())
    }

    #[test]
    fn chromium_modern_visits_resolve_referrers_sources_transitions_and_duration() -> Result<()> {
        let case_path = unique_case_path("chromium-deep-visits");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("chromium-deep-visits-source");
        let profile_dir = root
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        let conn = Connection::open(&history_path)?;
        conn.execute_batch(
            "ALTER TABLE visits ADD COLUMN from_visit INTEGER;
             ALTER TABLE visits ADD COLUMN opener_visit INTEGER;
             ALTER TABLE visits ADD COLUMN external_referrer_url TEXT;
             ALTER TABLE visits ADD COLUMN visit_duration INTEGER;
             CREATE TABLE visit_source(id INTEGER PRIMARY KEY, source INTEGER);
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://a.example/start', 'A', 1, 0, 13300000000000000, 0),
                    (2, 'https://b.example/redirect', 'B', 1, 0, 13300000001000000, 0),
                    (3, 'https://c.example/typed', 'C', 1, 1, 13300000002000000, 0);
             INSERT INTO visits(
                id, url, visit_time, from_visit, transition, opener_visit,
                external_referrer_url, visit_duration
             ) VALUES
                (1, 1, 13300000000000000, 0, 0, 0, NULL, NULL),
                (2, 2, 13300000001000000, 1, 2684354560, 0,
                    'https://outside.example/referrer', NULL),
                (3, 3, 13300000002000000, 2, 33554433, 1, NULL, 785432101);
             INSERT INTO visit_source(id, source) VALUES (2, 2), (3, 1);",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        assert_eq!(imported.visits_indexed, 3);
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let visit = |id| {
            entries
                .iter()
                .find(|entry| {
                    entry.metadata_json["artifact_kind"].as_str() == Some("browser_history_visit")
                        && entry.metadata_json["visit_id"].as_i64() == Some(id)
                })
                .expect("visit record")
        };
        let a = visit(1);
        let b = visit(2);
        let c = visit(3);
        assert_eq!(
            a.metadata_json["visit_source_label"].as_str(),
            Some("local")
        );
        assert_eq!(b.metadata_json["from_visit_id"].as_i64(), Some(1));
        assert_eq!(
            b.metadata_json["referrer_url"].as_str(),
            Some("https://a.example/start")
        );
        assert_eq!(
            b.metadata_json["referrer_visit_time_utc"].as_str(),
            chrome_time_to_rfc3339(13300000000000000).as_deref()
        );
        assert_eq!(
            b.metadata_json["external_referrer_url"].as_str(),
            Some("https://outside.example/referrer")
        );
        assert_eq!(
            b.metadata_json["transition_qualifiers"],
            serde_json::json!(["chain_end", "server_redirect"])
        );
        assert_eq!(
            b.metadata_json["transition_raw"].as_i64(),
            Some(2_684_354_560)
        );
        assert_eq!(b.metadata_json["is_redirect"].as_bool(), Some(true));
        assert_eq!(
            b.metadata_json["visit_source_label"].as_str(),
            Some("extension")
        );
        assert_eq!(c.metadata_json["from_visit_id"].as_i64(), Some(2));
        assert_eq!(
            c.metadata_json["referrer_url"].as_str(),
            Some("https://b.example/redirect")
        );
        assert_eq!(c.metadata_json["opener_visit_id"].as_i64(), Some(1));
        assert_eq!(
            c.metadata_json["opener_url"].as_str(),
            Some("https://a.example/start")
        );
        assert_eq!(c.metadata_json["transition_type"].as_str(), Some("typed"));
        assert_eq!(
            c.metadata_json["transition_qualifiers"],
            serde_json::json!(["from_address_bar"])
        );
        assert_eq!(c.metadata_json["typed_navigation"].as_bool(), Some(true));
        assert_eq!(c.metadata_json["user_initiated_hint"].as_bool(), Some(true));
        assert_eq!(
            c.metadata_json["visit_duration_microseconds"].as_i64(),
            Some(785432101)
        );
        assert_eq!(
            c.metadata_json["visit_duration_seconds"].as_f64(),
            Some(785.432101)
        );
        assert_eq!(
            c.metadata_json["visit_duration_human"].as_str(),
            Some("13m 5.4s")
        );
        assert_eq!(
            c.metadata_json["visit_source_label"].as_str(),
            Some("browsed(local)")
        );
        assert_eq!(c.metadata_json["browser_brand"].as_str(), Some("chrome"));
        for key in [
            "created_utc",
            "modified_utc",
            "accessed_utc",
            "mft_modified_utc",
        ] {
            assert!(c.metadata_json[key].is_null());
        }

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn chromium_old_history_and_lower_term_schema_import_without_errors() -> Result<()> {
        let case_path = unique_case_path("chromium-old-era");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-old-era-source");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        let conn = Connection::open(&history_path)?;
        conn.execute_batch(
            "CREATE TABLE keyword_search_terms(
                keyword_id INTEGER, url_id INTEGER, term TEXT, lower_term TEXT
             );
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://old.example/?q=Vintage', 'Old Chromium', 1, 1,
                     12900000000000000, 0);
             INSERT INTO visits(id, url, visit_time, transition)
             VALUES (1, 1, 12900000000000000, 1);
             INSERT INTO keyword_search_terms(keyword_id, url_id, term, lower_term)
             VALUES (1, 1, 'Vintage Search', 'vintage search');",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let visit = entry_with_artifact(&entries, "browser_history_visit");
        assert!(visit.metadata_json["visit_duration_microseconds"].is_null());
        assert!(visit.metadata_json["visit_duration_seconds"].is_null());
        assert!(visit.metadata_json["visit_duration_human"].is_null());
        assert!(visit.metadata_json["from_visit_id"].is_null());
        assert!(visit.metadata_json["referrer_url"].is_null());
        assert!(visit.metadata_json["opener_visit_id"].is_null());
        assert!(visit.metadata_json["external_referrer_url"].is_null());
        assert_eq!(
            visit.metadata_json["visit_source_label"].as_str(),
            Some("local")
        );
        let search = entry_with_artifact(&entries, "browser_search_term");
        assert_eq!(search.metadata_json["keyword_id"].as_i64(), Some(1));
        assert_eq!(
            search.metadata_json["lower_term"].as_str(),
            Some("vintage search")
        );
        assert!(search.metadata_json["normalized_term"].is_null());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_transition_decoder_covers_all_core_types_and_qualifiers() {
        let core_types = [
            "link",
            "typed",
            "auto_bookmark",
            "auto_subframe",
            "manual_subframe",
            "generated",
            "auto_toplevel",
            "form_submit",
            "reload",
            "keyword",
            "keyword_generated",
        ];
        for (raw, expected) in core_types.iter().enumerate() {
            assert_eq!(chromium_transition_type(raw as i64), *expected);
        }
        assert_eq!(chromium_transition_type(11), "unknown");
        assert_eq!(
            chromium_transition_qualifiers(i64::from(i32::MIN)),
            vec!["server_redirect"]
        );
        let all_qualifiers = 0x0080_0000_i64
            | 0x0100_0000
            | 0x0200_0000
            | 0x0400_0000
            | 0x0800_0000
            | 0x1000_0000
            | 0x2000_0000
            | 0x4000_0000
            | 0x8000_0000;
        assert_eq!(
            chromium_transition_qualifiers(all_qualifiers),
            vec![
                "blocked",
                "forward_back",
                "from_address_bar",
                "home_page",
                "from_api",
                "chain_start",
                "chain_end",
                "client_redirect",
                "server_redirect",
            ]
        );
        for (mask, expected) in [
            (0x0080_0000, "blocked"),
            (0x0100_0000, "forward_back"),
            (0x0200_0000, "from_address_bar"),
            (0x0400_0000, "home_page"),
            (0x0800_0000, "from_api"),
            (0x1000_0000, "chain_start"),
            (0x2000_0000, "chain_end"),
            (0x4000_0000, "client_redirect"),
            (0x8000_0000, "server_redirect"),
        ] {
            assert_eq!(chromium_transition_qualifiers(mask), vec![expected]);
        }
    }

    #[test]
    fn chromium_brand_detection_is_case_insensitive_and_slash_agnostic() {
        assert_eq!(
            chromium_browser_brand(r"C:\Users\A\Google\Chrome\User Data\Default"),
            Some("chrome")
        );
        assert_eq!(
            chromium_browser_brand("/Users/a/MICROSOFT/EDGE/Default"),
            Some("edge")
        );
        assert_eq!(
            chromium_browser_brand("/home/a/.config/Chromium/Default"),
            Some("chromium")
        );
        assert_eq!(
            chromium_browser_brand("/home/a/.config/BraveSoftware/Brave-Browser/Default"),
            Some("brave")
        );
        assert_eq!(
            chromium_browser_brand("/Users/a/Library/Application Support/com.operasoftware.Opera"),
            Some("opera")
        );
        assert_eq!(chromium_browser_brand("/evidence/unknown/Profile"), None);
    }

    #[test]
    fn chromium_profile_derivation_keys_and_prefixes_are_distinct_and_deterministic() {
        let default_path = "Users/A/AppData/Local/Google/Chrome/User Data/Default";
        let profile_path = "Users/A/AppData/Local/Google/Chrome/User Data/Profile 1";
        let default_key = browser_profile_derivation_key(default_path, Some(0));
        assert_eq!(
            default_key,
            browser_profile_derivation_key(default_path, Some(0))
        );
        let profile_key = browser_profile_derivation_key(profile_path, Some(0));
        assert_ne!(default_key, profile_key);
        assert_ne!(
            default_key,
            browser_profile_derivation_key(default_path, Some(1))
        );
        assert_ne!(
            browser_profile_derivation_key("home/alice/Default", Some(0)),
            browser_profile_derivation_key("home/alice/default", Some(0)),
            "case-sensitive filesystems may contain both profile paths"
        );
        assert_ne!(
            browser_profile_logical_prefix(default_path, Some(0), &default_key),
            browser_profile_logical_prefix(profile_path, Some(0), &profile_key)
        );
        let staging_a = auto_browser_profile_staging_root(
            Path::new("imports"),
            7,
            "Default",
            &default_key,
            101,
        );
        assert_eq!(
            staging_a,
            auto_browser_profile_staging_root(
                Path::new("imports"),
                7,
                "Default",
                &default_key,
                101,
            )
        );
        assert_ne!(
            staging_a,
            auto_browser_profile_staging_root(
                Path::new("imports"),
                8,
                "Default",
                &default_key,
                102,
            )
        );
    }

    #[test]
    fn chromium_modern_downloads_include_chains_labels_progress_and_outcomes() -> Result<()> {
        let case_path = unique_case_path("chromium-modern-downloads");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-modern-downloads-source");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        let conn = Connection::open(&history_path)?;
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                current_path TEXT,
                target_path TEXT,
                start_time INTEGER,
                end_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                danger_type INTEGER,
                interrupt_reason INTEGER,
                referrer TEXT,
                tab_url TEXT,
                mime_type TEXT,
                guid TEXT,
                site_url TEXT,
                tab_referrer_url TEXT,
                original_mime_type TEXT,
                last_access_time INTEGER,
                opened INTEGER,
                hash BLOB
             );
             CREATE TABLE downloads_url_chains(
                id INTEGER, chain_index INTEGER, url TEXT
             );
             INSERT INTO downloads(
                id, current_path, target_path, start_time, end_time,
                received_bytes, total_bytes, state, danger_type, interrupt_reason,
                referrer, tab_url, mime_type, guid, site_url, tab_referrer_url,
                original_mime_type, last_access_time, opened, hash
             ) VALUES
                (1, 'C:\\Temp\\complete.bin', 'C:\\Downloads\\complete.bin',
                 13300000000000000, 13300000001800000, 1495112, 1495112,
                 1, 0, 0, 'https://ref.example/complete',
                 'https://tab.example/complete', 'application/octet-stream',
                 'guid-complete', 'https://site.example/',
                 'https://tab-ref.example/', 'application/x-download',
                 13300000002000000, 1, X'01020304'),
                (2, 'C:\\Temp\\partial.iso.crdownload', 'C:\\Downloads\\partial.iso',
                 13300000100000000, 13300000142300000, 1234567, 4500000,
                 4, 8, 21, 'https://ref.example/interrupted',
                 'https://tab.example/interrupted', 'application/octet-stream',
                 'guid-interrupted', 'https://download.example/',
                 'https://tab-ref.example/interrupted', 'application/x-iso9660-image',
                 13300000150000000, 0, NULL);
             INSERT INTO downloads_url_chains(id, chain_index, url) VALUES
                (1, 1, 'https://cdn.example/complete.bin'),
                (1, 0, 'https://origin.example/complete'),
                (2, 2, 'https://cdn.example/partial.iso'),
                (2, 0, 'https://origin.example/download'),
                (2, 1, 'https://redirect.example/token');",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_download"), 2);
        let download = |id| {
            entries
                .iter()
                .find(|entry| {
                    entry.metadata_json["artifact_kind"].as_str() == Some("browser_download")
                        && entry.metadata_json["download_id"].as_i64() == Some(id)
                })
                .expect("download record")
        };
        let complete = download(1);
        assert_eq!(
            complete.metadata_json["state_label"].as_str(),
            Some("complete")
        );
        assert_eq!(
            complete.metadata_json["danger_type_label"].as_str(),
            Some("not_dangerous")
        );
        assert_eq!(
            complete.metadata_json["url_chain"],
            serde_json::json!([
                "https://origin.example/complete",
                "https://cdn.example/complete.bin"
            ])
        );
        assert_eq!(complete.metadata_json["url_chain_total"].as_u64(), Some(2));
        assert_eq!(
            complete.metadata_json["url_chain_omitted"].as_u64(),
            Some(0)
        );
        assert_eq!(
            complete.metadata_json["url_chain_complete"].as_bool(),
            Some(true)
        );
        assert_eq!(
            complete.metadata_json["original_url"].as_str(),
            Some("https://origin.example/complete")
        );
        assert_eq!(
            complete.metadata_json["download_url"].as_str(),
            Some("https://cdn.example/complete.bin")
        );
        assert_eq!(complete.metadata_json["opened"].as_bool(), Some(true));
        assert_eq!(complete.metadata_json["hash"].as_str(), Some("01020304"));
        assert_eq!(
            complete.metadata_json["guid"].as_str(),
            Some("guid-complete")
        );
        assert_eq!(
            complete.metadata_json["site_url"].as_str(),
            Some("https://site.example/")
        );
        assert_eq!(
            complete.metadata_json["tab_referrer_url"].as_str(),
            Some("https://tab-ref.example/")
        );
        assert_eq!(
            complete.metadata_json["original_mime_type"].as_str(),
            Some("application/x-download")
        );
        assert_eq!(
            complete.metadata_json["referrer"].as_str(),
            Some("https://ref.example/complete")
        );
        assert_eq!(
            complete.metadata_json["mime_type"].as_str(),
            Some("application/octet-stream")
        );
        assert_eq!(
            complete.metadata_json["percent_complete"].as_f64(),
            Some(100.0)
        );
        assert_eq!(
            complete.metadata_json["duration_seconds"].as_f64(),
            Some(1.8)
        );
        assert_eq!(
            complete.metadata_json["duration_human"].as_str(),
            Some("1.8s")
        );
        assert_eq!(
            complete.metadata_json["outcome_summary"].as_str(),
            Some("complete - 1,495,112 bytes in 1.8s")
        );

        let interrupted = download(2);
        assert_eq!(
            interrupted.metadata_json["state_label"].as_str(),
            Some("interrupted")
        );
        assert_eq!(
            interrupted.metadata_json["danger_type_label"].as_str(),
            Some("potentially_unwanted")
        );
        assert_eq!(
            interrupted.metadata_json["interrupt_reason_label"].as_str(),
            Some("network_timeout")
        );
        let percent = interrupted.metadata_json["percent_complete"]
            .as_f64()
            .expect("percent complete");
        assert!((percent - 27.43482222222222).abs() < 0.000001);
        assert_eq!(
            interrupted.metadata_json["url_chain"],
            serde_json::json!([
                "https://origin.example/download",
                "https://redirect.example/token",
                "https://cdn.example/partial.iso"
            ])
        );
        assert_eq!(
            interrupted.metadata_json["original_url"].as_str(),
            Some("https://origin.example/download")
        );
        assert_eq!(
            interrupted.metadata_json["download_url"].as_str(),
            Some("https://cdn.example/partial.iso")
        );
        assert_eq!(
            interrupted.metadata_json["duration_human"].as_str(),
            Some("42.3s")
        );
        assert_eq!(
            interrupted.metadata_json["outcome_summary"].as_str(),
            Some("interrupted at 1,234,567 of 4,500,000 bytes (27%) after 42.3s - network_timeout")
        );
        assert_eq!(
            interrupted.metadata_json["last_access_time_utc"].as_str(),
            chrome_time_to_rfc3339(13300000150000000).as_deref()
        );
        assert_eq!(interrupted.metadata_json["opened"].as_bool(), Some(false));
        for entry in [complete, interrupted] {
            for key in [
                "created_utc",
                "modified_utc",
                "accessed_utc",
                "mft_modified_utc",
            ] {
                assert!(entry.metadata_json[key].is_null());
            }
        }

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_legacy_download_schema_uses_url_and_full_path_fallbacks() -> Result<()> {
        let case_path = unique_case_path("chromium-legacy-downloads");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-legacy-downloads-source");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        let conn = Connection::open(&history_path)?;
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                full_path TEXT,
                url TEXT,
                start_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                end_time INTEGER,
                opened INTEGER
             );
             INSERT INTO downloads(
                id, full_path, url, start_time, received_bytes, total_bytes,
                state, end_time, opened
             ) VALUES (
                9, 'C:\\Users\\Old\\Downloads\\legacy.zip',
                'https://legacy.example/files/legacy.zip',
                1290000000, 4096, 4096, 1, 1290000002, 1
             );",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let download = entry_with_artifact(&entries, "browser_download");
        assert_eq!(
            download.metadata_json["file_name"].as_str(),
            Some("legacy.zip")
        );
        assert_eq!(
            download.metadata_json["target_path"].as_str(),
            Some("C:\\Users\\Old\\Downloads\\legacy.zip")
        );
        assert_eq!(
            download.metadata_json["full_path"].as_str(),
            Some("C:\\Users\\Old\\Downloads\\legacy.zip")
        );
        assert_eq!(
            download.metadata_json["download_url"].as_str(),
            Some("https://legacy.example/files/legacy.zip")
        );
        assert!(download.metadata_json["original_url"].is_null());
        assert_eq!(download.metadata_json["url_chain"], serde_json::json!([]));
        assert_eq!(
            download.metadata_json["state_label"].as_str(),
            Some("complete")
        );
        assert!(download.metadata_json["danger_type_label"].is_null());
        assert!(download.metadata_json["interrupt_reason_label"].is_null());
        assert_eq!(download.metadata_json["opened"].as_bool(), Some(true));
        assert_eq!(
            download.metadata_json["start_time_utc"].as_str(),
            Some("2010-11-17T13:20:00+00:00")
        );
        assert_eq!(
            download.metadata_json["end_time_utc"].as_str(),
            Some("2010-11-17T13:20:02+00:00")
        );
        assert_eq!(
            download.metadata_json["download_time_basis"].as_str(),
            Some("unix_seconds_legacy")
        );
        assert!(download.metadata_json["start_time_chrome"].is_null());
        assert_eq!(
            download.metadata_json["start_time_unix_seconds"].as_i64(),
            Some(1290000000)
        );
        assert_eq!(
            download.metadata_json["duration_human"].as_str(),
            Some("2.0s")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_zero_sentinel_times_and_empty_hashes_do_not_fabricate_events() -> Result<()> {
        let case_path = unique_case_path("chromium-zero-times");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-zero-times-source");
        let history_path = profile_dir.join("History");
        create_empty_chromium_history_core(&history_path)?;
        Connection::open(&history_path)?.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                start_time INTEGER,
                end_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                last_access_time INTEGER,
                hash BLOB
             );
             INSERT INTO downloads(
                id, target_path, start_time, end_time, received_bytes,
                total_bytes, state, last_access_time, hash
             ) VALUES (
                1, 'C:\\Downloads\\pending.bin', 13300000000000000,
                0, 0, 0, 0, 0, X''
             );",
        )?;
        Connection::open(profile_dir.join("Shortcuts"))?.execute_batch(
            "CREATE TABLE omni_box_shortcuts(
                id TEXT PRIMARY KEY, text TEXT, last_access_time INTEGER
             );
             INSERT INTO omni_box_shortcuts(id, text, last_access_time)
             VALUES ('zero-time', 'unfinished typing', 0);",
        )?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let download = entry_with_artifact(&entries, "browser_download");
        assert!(download.metadata_json["end_time_utc"].is_null());
        assert!(download.metadata_json["last_access_time_utc"].is_null());
        assert!(download.metadata_json["duration_seconds"].is_null());
        assert!(download.metadata_json["duration_human"].is_null());
        assert!(download.metadata_json["percent_complete"].is_null());
        assert!(download.metadata_json["hash"].is_null());
        let shortcut = entry_with_artifact(&entries, "browser_omnibox_shortcut");
        assert!(shortcut.metadata_json["last_access_time_utc"].is_null());
        assert!(shortcut.metadata_json["last_access_utc"].is_null());
        assert!(!download.metadata_json.to_string().contains("1601-01-01"));
        assert!(!shortcut.metadata_json.to_string().contains("1601-01-01"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_download_label_decoders_cover_known_and_unknown_values() {
        assert_eq!(format_i64_grouped(42), "42");
        assert_eq!(format_i64_grouped(12_345), "12,345");
        assert_eq!(format_i64_grouped(12_345_678), "12,345,678");
        assert_eq!(format_i64_grouped(i64::MIN), "-9,223,372,036,854,775,808");
        for (raw, expected) in [
            (0, "in_progress"),
            (1, "complete"),
            (2, "cancelled"),
            (3, "obsolete_bug_140687"),
            (4, "interrupted"),
        ] {
            assert_eq!(chromium_download_state_label(raw), expected);
        }
        assert_eq!(chromium_download_state_label(99), "unknown (99)");
        for (raw, expected) in [
            (0, "not_dangerous"),
            (1, "dangerous_file"),
            (2, "dangerous_url"),
            (3, "dangerous_content"),
            (4, "maybe_dangerous_content"),
            (5, "uncommon_content"),
            (6, "user_validated"),
            (7, "dangerous_host"),
            (8, "potentially_unwanted"),
        ] {
            assert_eq!(chromium_download_danger_type_label(raw), expected);
        }
        assert_eq!(chromium_download_danger_type_label(99), "unknown (99)");
        for (raw, expected) in [
            (0, "none"),
            (1, "file_failed"),
            (2, "file_access_denied"),
            (3, "file_no_space"),
            (5, "file_name_too_long"),
            (6, "file_too_large"),
            (7, "file_virus_infected"),
            (10, "file_transient_error"),
            (11, "file_blocked"),
            (12, "file_security_check_failed"),
            (13, "file_too_short"),
            (14, "file_hash_mismatch"),
            (15, "file_same_as_source"),
            (20, "network_failed"),
            (21, "network_timeout"),
            (22, "network_disconnected"),
            (23, "network_server_down"),
            (24, "network_invalid_request"),
            (30, "server_failed"),
            (31, "server_no_range"),
            (33, "server_bad_content"),
            (34, "server_unauthorized"),
            (35, "server_cert_problem"),
            (36, "server_forbidden"),
            (37, "server_unreachable"),
            (38, "server_content_length_mismatch"),
            (40, "user_canceled"),
            (41, "user_shutdown"),
            (50, "crash"),
        ] {
            assert_eq!(chromium_download_interrupt_reason_label(raw), expected);
        }
        assert_eq!(chromium_download_interrupt_reason_label(99), "unknown (99)");
    }

    #[test]
    fn chromium_login_retains_encrypted_password_as_labelled_ciphertext() -> Result<()> {
        let profile_dir = unique_temp_dir("chromium-login-ciphertext");
        let login_path = profile_dir.join("Login Data");
        let conn = Connection::open(&login_path)?;
        conn.execute_batch(
            "CREATE TABLE logins(
                origin_url TEXT,
                action_url TEXT,
                username_value TEXT,
                date_created INTEGER,
                date_last_used INTEGER,
                times_used INTEGER,
                password_value BLOB
             );
             INSERT INTO logins(
                origin_url, action_url, username_value, date_created,
                date_last_used, times_used, password_value
             ) VALUES (
                'https://example.test/login', 'https://example.test/session',
                'alice', 1, 2, 3, X'0102A0FF'
             );",
        )?;
        drop(conn);

        let mut records = Vec::new();
        let count = stream_chromium_login_records(&profile_dir, usize::MAX, &mut |record| {
            records.push(record);
            Ok(())
        })?;
        assert_eq!(count, 1);
        let metadata: serde_json::Value = serde_json::from_str(&records[0].metadata_json)?;
        assert_eq!(metadata["username"].as_str(), Some("alice"));
        assert_eq!(
            metadata["password_ciphertext_hex"].as_str(),
            Some("0102A0FF")
        );
        assert_eq!(metadata["password_ciphertext_bytes"].as_u64(), Some(4));
        assert_eq!(metadata["sensitive_value_present"].as_bool(), Some(true));
        assert!(metadata["password_note"]
            .as_str()
            .is_some_and(|value| value.contains("not decrypted")));

        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_autofill_uses_unix_seconds_and_imports_plain_text_fields() -> Result<()> {
        let case_path = unique_case_path("chromium-autofill");
        create_test_case(&case_path)?;
        let root = unique_temp_dir("chromium-autofill-source");
        let profile_dir = root
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        create_test_chromium_web_data(&profile_dir.join("Web Data"))?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_autofill"), 2);
        let email = entries
            .iter()
            .find(|entry| entry.metadata_json["name"].as_str() == Some("email"))
            .expect("email autofill row");
        assert_eq!(
            email.metadata_json["value"].as_str(),
            Some("examiner@example.test")
        );
        assert_eq!(email.metadata_json["count"].as_i64(), Some(3));
        assert_eq!(
            email.metadata_json["date_created_utc"].as_str(),
            Some("2023-11-14T22:13:20+00:00")
        );
        assert_eq!(
            email.metadata_json["date_last_used_utc"].as_str(),
            Some("2023-11-14T23:13:20+00:00")
        );
        assert_eq!(
            email.metadata_json["source_artifact"].as_str(),
            Some("Web Data")
        );
        assert_eq!(
            email.metadata_json["browser_brand"].as_str(),
            Some("chrome")
        );
        assert_eq!(
            email.metadata_json["category_sub"].as_str(),
            Some("Autofill")
        );
        for key in [
            "created_utc",
            "modified_utc",
            "accessed_utc",
            "mft_modified_utc",
        ] {
            assert!(email.metadata_json[key].is_null());
        }
        let note = entries
            .iter()
            .find(|entry| entry.metadata_json["name"].as_str() == Some("case-note"))
            .expect("case-note autofill row");
        assert_eq!(
            note.metadata_json["value"].as_str(),
            Some("typed evidence note")
        );
        assert_eq!(note.metadata_json["count"].as_i64(), Some(2));
        assert_eq!(
            note.metadata_json["date_created_utc"].as_str(),
            Some("2023-11-16T02:00:00+00:00")
        );
        assert_eq!(
            note.metadata_json["date_last_used_utc"].as_str(),
            Some("2023-11-16T04:00:00+00:00")
        );
        let conn = open_existing_case(&case_path)?;
        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![imported.job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        assert!(parameters["shortcuts_file"]
            .as_str()
            .is_some_and(|path| path.ends_with("Shortcuts")));
        assert!(parameters["web_data_file"]
            .as_str()
            .is_some_and(|path| path.ends_with("Web Data")));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn chromium_legacy_autofill_dates_are_aggregated_by_pair_id() -> Result<()> {
        let case_path = unique_case_path("chromium-legacy-autofill");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-legacy-autofill-source");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        let conn = Connection::open(profile_dir.join("Web Data"))?;
        conn.execute_batch(
            "CREATE TABLE autofill(
                pair_id INTEGER PRIMARY KEY,
                name TEXT,
                value TEXT,
                count INTEGER
             );
             CREATE TABLE autofill_dates(pair_id INTEGER, date_created INTEGER);
             INSERT INTO autofill(pair_id, name, value, count)
             VALUES (42, 'legacy-field', 'legacy typed value', 4);
             INSERT INTO autofill_dates(pair_id, date_created)
             VALUES (42, 0), (42, 1600003600), (42, 1600000000), (42, 1600001800);",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let autofill = entry_with_artifact(&entries, "browser_autofill");
        assert_eq!(autofill.metadata_json["rowid"].as_i64(), Some(42));
        assert_eq!(autofill.metadata_json["count"].as_i64(), Some(4));
        assert_eq!(
            autofill.metadata_json["date_created_utc"].as_str(),
            Some("2020-09-13T12:26:40+00:00")
        );
        assert_eq!(
            autofill.metadata_json["date_last_used_utc"].as_str(),
            Some("2020-09-13T13:26:40+00:00")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_shortcuts_import_exact_omnibox_text_and_last_access_time() -> Result<()> {
        let case_path = unique_case_path("chromium-shortcuts");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-shortcuts-source");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        create_test_chromium_shortcuts(&profile_dir.join("Shortcuts"))?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let shortcut = entry_with_artifact(&entries, "browser_omnibox_shortcut");
        assert_eq!(
            shortcut.metadata_json["text"].as_str(),
            Some("example forensic search")
        );
        assert_eq!(
            shortcut.metadata_json["url"].as_str(),
            Some("https://search.example.test/?q=example+forensic+search")
        );
        assert_eq!(
            shortcut.metadata_json["last_access_time_utc"].as_str(),
            Some("2022-06-18T04:27:05+00:00")
        );
        assert_eq!(shortcut.metadata_json["number_of_hits"].as_i64(), Some(7));
        assert_eq!(
            shortcut.metadata_json["source_artifact"].as_str(),
            Some("Shortcuts")
        );
        assert!(shortcut
            .logical_path
            .starts_with("/Browser Activities/Omnibox/shortcut-guid-1-example_forensic_search"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn chromium_corrupt_web_data_and_shortcuts_failures_are_disclosed() -> Result<()> {
        let case_path = unique_case_path("chromium-deep-reader-errors");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("chromium-deep-reader-errors-source");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        fs::write(profile_dir.join("Web Data"), b"not a sqlite database")?;
        fs::write(profile_dir.join("Shortcuts"), b"not a sqlite database")?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.entries_indexed, 0);
        assert!(imported
            .parse_errors
            .iter()
            .any(|error| error.starts_with("autofill:")));
        assert!(imported
            .parse_errors
            .iter()
            .any(|error| error.starts_with("omnibox shortcuts:")));
        let conn = open_existing_case(&case_path)?;
        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![imported.job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        let persisted_errors = parameters["parse_errors"]
            .as_array()
            .expect("persisted parse errors");
        assert!(persisted_errors.iter().any(|error| error
            .as_str()
            .is_some_and(|error| error.starts_with("autofill:"))));
        assert!(persisted_errors.iter().any(|error| error
            .as_str()
            .is_some_and(|error| error.starts_with("omnibox shortcuts:"))));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn ext_auto_chromium_import_keeps_source_macb_and_persists_reader_errors() -> Result<()> {
        let case_path = unique_case_path("chromium-ext-auto-provenance");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("chromium-ext-auto-evidence");
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let staging_dir = unique_temp_dir("chromium-ext-auto-staging");
        create_empty_chromium_history_core(&staging_dir.join("History"))?;
        create_test_chromium_shortcuts(&staging_dir.join("Shortcuts"))?;
        fs::write(staging_dir.join("Web Data"), b"not a sqlite database")?;

        let source_profile = "/home/alice/.config/Google/Chrome/User Data/Default";
        let source_created = "2020-01-02T03:04:05+00:00";
        let source_modified = "2020-02-03T04:05:06+00:00";
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_jobs(
                case_id, evidence_id, job_type, status, parameters_json, started_at
             ) VALUES (?1, ?2, 'filesystem_index', 'running', ?3,
                       strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                case_id,
                evidence_id,
                serde_json::json!({"parse_browsers": true}).to_string()
            ],
        )?;
        let job_id = conn.last_insert_rowid();
        for name in ["History", "Shortcuts", "Web Data"] {
            let exact_path = format!("{source_profile}/{name}");
            let logical_path = format!("/Image Analysis/Volumes/001-ext{exact_path}");
            let size =
                i64::try_from(fs::metadata(staging_dir.join(name))?.len()).unwrap_or(i64::MAX);
            upsert_filesystem_entry(
                &conn,
                case_id,
                evidence_id,
                &logical_path,
                name,
                "file",
                Some(size),
                &serde_json::json!({
                    "artifact_kind": "filesystem_entry",
                    "filesystem_parser": "ext4",
                    "partition_index": 1,
                    "ext_path": exact_path,
                    "created_utc": source_created,
                    "modified_utc": source_modified,
                })
                .to_string(),
                job_id,
            )?;
        }
        let shortcut_source_id: i64 = conn.query_row(
            "SELECT id FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2 AND name = 'Shortcuts'",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;

        let import_data = collect_chromium_history_import(&staging_dir, usize::MAX)?;
        assert!(import_data
            .parse_errors
            .iter()
            .any(|error| error.starts_with("autofill:")));
        assert_eq!(
            persist_auto_browser_profile_import(
                &conn,
                case_id,
                evidence_id,
                job_id,
                source_profile,
                Some(0),
                &staging_dir,
                &import_data,
            )?,
            1
        );

        let shortcut_metadata: String = conn.query_row(
            "SELECT metadata_json FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2
               AND json_extract(metadata_json, '$.artifact_kind') =
                   'browser_omnibox_shortcut'",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;
        let shortcut: serde_json::Value = serde_json::from_str(&shortcut_metadata)?;
        assert_eq!(
            shortcut["source_entry_id"].as_i64(),
            Some(shortcut_source_id)
        );
        assert_eq!(
            shortcut["source_file_time_basis"].as_str(),
            Some("original_evidence_filesystem")
        );
        assert_eq!(
            shortcut["source_file_created_utc"].as_str(),
            Some(source_created)
        );
        assert_eq!(
            shortcut["source_file_modified_utc"].as_str(),
            Some(source_modified)
        );
        assert_eq!(
            shortcut["source_profile_path_exact"].as_str(),
            Some(source_profile)
        );
        assert_eq!(shortcut["volume_index_zero_based"].as_u64(), Some(0));
        for key in [
            "created_utc",
            "modified_utc",
            "accessed_utc",
            "mft_modified_utc",
        ] {
            assert!(shortcut[key].is_null());
        }

        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        assert_eq!(parameters["browser_parse_error_count"].as_u64(), Some(1));
        let disclosure = &parameters["auto_browser_imports"][0];
        assert_eq!(
            disclosure["source_profile_path"].as_str(),
            Some(source_profile)
        );
        assert_eq!(disclosure["status"].as_str(), Some("completed_with_errors"));
        assert_eq!(disclosure["parse_error_count"].as_u64(), Some(1));
        assert_eq!(disclosure["parse_error_samples_omitted"].as_u64(), Some(0));
        assert!(disclosure["parse_errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|error| error.starts_with("autofill:")))));

        let public_disclosures = browser_auto_import_disclosures(&case_path, evidence_id)?;
        assert_eq!(public_disclosures.len(), 1);
        assert_eq!(
            public_disclosures[0]["source_profile_path"].as_str(),
            Some(source_profile)
        );
        assert_eq!(public_disclosures[0]["parse_error_count"].as_u64(), Some(1));

        conn.execute(
            "INSERT INTO evidence_jobs(
                case_id, evidence_id, job_type, status, parameters_json, started_at
             ) VALUES (?1, ?2, 'filesystem_index', 'completed', '{}',
                       strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![case_id, evidence_id],
        )?;
        assert!(browser_auto_import_disclosures(&case_path, evidence_id)?.is_empty());

        drop(conn);
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        let _ = fs::remove_dir_all(staging_dir);
        Ok(())
    }

    #[test]
    fn ext_browser_late_nested_sources_are_relinked_in_bounded_pages() -> Result<()> {
        let case_path = unique_case_path("ext-browser-late-provenance");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("ext-browser-late-provenance-source");
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO evidence_jobs(
                case_id, evidence_id, job_type, status, parameters_json, started_at
             ) VALUES (?1, ?2, 'filesystem_index', 'running', '{}',
                       strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![case_id, evidence_id],
        )?;
        let job_id = conn.last_insert_rowid();
        let source_path = "/home/alice/.config/chromium/Default/Network/Cookies";
        let source_created = "2024-01-02T03:04:05+00:00";
        upsert_filesystem_entry(
            &conn,
            case_id,
            evidence_id,
            "/Image Analysis/Volumes/001-ext/home/alice/.config/chromium/Default/Network/Cookies",
            "Cookies",
            "file",
            Some(4096),
            &serde_json::json!({
                "artifact_kind": "filesystem_entry",
                "filesystem_parser": "ext4",
                "partition_index": 1,
                "ext_path": source_path,
                "created_utc": source_created,
            })
            .to_string(),
            job_id,
        )?;
        let source_entry_id = conn.last_insert_rowid();

        for index in 0..70 {
            upsert_filesystem_entry(
                &conn,
                case_id,
                evidence_id,
                &format!("/Parsed Artifacts/Browser/cookies/{index:03}.record"),
                "canonical-cookie-name",
                "record",
                None,
                &serde_json::json!({
                    "artifact_kind": "browser_cookie",
                    "derived_artifact": true,
                    "volume_index_zero_based": 0,
                    "source_artifact_path_exact": source_path,
                    "source_path_exact": source_path,
                    "canonical_database_value": "do-not-rename",
                })
                .to_string(),
                job_id,
            )?;
        }

        assert_eq!(
            relink_ext_browser_derived_provenance(&conn, case_id, evidence_id, job_id, 1,)?,
            70
        );
        let metadata_json: String = conn.query_row(
            "SELECT metadata_json FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2
               AND json_extract(metadata_json, '$.canonical_database_value') = 'do-not-rename'
             ORDER BY id LIMIT 1",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
        assert_eq!(metadata["source_entry_id"].as_i64(), Some(source_entry_id));
        assert_eq!(
            metadata["source_file_created_utc"].as_str(),
            Some(source_created)
        );
        assert_eq!(
            metadata["source_file_time_basis"].as_str(),
            Some("original_evidence_filesystem")
        );
        assert_eq!(metadata["source_path_exact"].as_str(), Some(source_path));
        assert_eq!(
            metadata["canonical_database_value"].as_str(),
            Some("do-not-rename")
        );

        drop(conn);
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn chromium_new_record_kinds_are_idempotent_and_keep_original_source_provenance() -> Result<()>
    {
        let case_path = unique_case_path("chromium-deep-idempotent");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("chromium-deep-idempotent-source");
        let profile_dir = evidence_dir
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        create_empty_chromium_history_core(&profile_dir.join("History"))?;
        create_test_chromium_shortcuts(&profile_dir.join("Shortcuts"))?;
        create_test_chromium_web_data(&profile_dir.join("Web Data"))?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let base_entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let shortcuts_source = base_entries
            .iter()
            .find(|entry| entry.name == "Shortcuts")
            .expect("indexed Shortcuts");
        let shortcuts_source_id = shortcuts_source.id;
        let shortcuts_created = shortcuts_source.metadata_json["created_utc"]
            .as_str()
            .expect("Shortcuts created time")
            .to_string();
        let shortcuts_modified = shortcuts_source.metadata_json["modified_utc"]
            .as_str()
            .expect("Shortcuts modified time")
            .to_string();
        let web_data_source = base_entries
            .iter()
            .find(|entry| entry.name == "Web Data")
            .expect("indexed Web Data");
        let web_data_source_id = web_data_source.id;
        let web_data_created = web_data_source.metadata_json["created_utc"]
            .as_str()
            .expect("Web Data created time")
            .to_string();
        let web_data_modified = web_data_source.metadata_json["modified_utc"]
            .as_str()
            .expect("Web Data modified time")
            .to_string();
        let options = ImportBrowserArtifactsIntoEvidenceOptions {
            evidence_id,
            history_path: profile_dir.clone(),
            max_visits: 0,
            source_profile_path: "Google/Chrome/User Data/Default".to_string(),
            volume_index_zero_based: None,
            legacy_evidence_name: None,
        };
        let first = import_browser_artifacts_into_evidence(&case_path, options.clone())?;
        let after_first = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let first_paths = after_first
            .iter()
            .filter(|entry| entry.metadata_json["browser_derivation_key"].is_string())
            .map(|entry| entry.logical_path.clone())
            .collect::<HashSet<_>>();
        let second = import_browser_artifacts_into_evidence(&case_path, options)?;
        let after_second = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let second_paths = after_second
            .iter()
            .filter(|entry| entry.metadata_json["browser_derivation_key"].is_string())
            .map(|entry| entry.logical_path.clone())
            .collect::<HashSet<_>>();
        assert_eq!(first.entries_indexed, 3);
        assert_eq!(second.entries_indexed, 3);
        assert_eq!(first_paths, second_paths);
        assert_eq!(second_paths.len(), 3);
        assert_eq!(list_evidence(&case_path)?.len(), 1);
        assert_eq!(after_second.len(), base_entries.len() + 3);
        assert_eq!(artifact_count(&after_second, "browser_omnibox_shortcut"), 1);
        assert_eq!(artifact_count(&after_second, "browser_autofill"), 2);
        for entry in after_second.iter().filter(|entry| {
            matches!(
                entry.metadata_json["artifact_kind"].as_str(),
                Some("browser_omnibox_shortcut" | "browser_autofill")
            )
        }) {
            assert_eq!(
                entry.metadata_json["source_file_time_basis"].as_str(),
                Some("original_evidence_filesystem")
            );
            assert_eq!(
                entry.metadata_json["browser_brand"].as_str(),
                Some("chrome")
            );
            for key in [
                "created_utc",
                "modified_utc",
                "accessed_utc",
                "mft_modified_utc",
            ] {
                assert!(entry.metadata_json[key].is_null());
            }
        }
        let shortcut = entry_with_artifact(&after_second, "browser_omnibox_shortcut");
        assert_eq!(
            shortcut.metadata_json["source_entry_id"].as_i64(),
            Some(shortcuts_source_id)
        );
        assert_eq!(
            shortcut.metadata_json["source_file_created_utc"].as_str(),
            Some(shortcuts_created.as_str())
        );
        assert_eq!(
            shortcut.metadata_json["source_file_modified_utc"].as_str(),
            Some(shortcuts_modified.as_str())
        );
        let autofill = entry_with_artifact(&after_second, "browser_autofill");
        assert_eq!(
            autofill.metadata_json["source_entry_id"].as_i64(),
            Some(web_data_source_id)
        );
        assert_eq!(
            autofill.metadata_json["source_file_created_utc"].as_str(),
            Some(web_data_created.as_str())
        );
        assert_eq!(
            autofill.metadata_json["source_file_modified_utc"].as_str(),
            Some(web_data_modified.as_str())
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn derived_browser_import_is_idempotent_retires_legacy_and_preserves_bookmark() -> Result<()> {
        let case_path = unique_case_path("derived-browser-idempotent");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("derived-browser-idempotent-source");
        let profile_dir = evidence_dir.join("Profile");
        fs::create_dir_all(&profile_dir)?;
        create_test_chromium_history(&profile_dir.join("History"))?;

        let parent_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id: parent_evidence_id,
                max_entries: 100,
            },
        )?;
        let base_entries = list_filesystem_entries(&case_path, Some(parent_evidence_id))?;
        let history_source = base_entries
            .iter()
            .find(|entry| entry.name == "History")
            .expect("indexed source History file");
        let source_created = history_source.metadata_json["created_utc"]
            .as_str()
            .expect("local source created time")
            .to_string();
        let legacy_name = "History profile: Profile (auto-parsed from parent)".to_string();
        let legacy = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: Some(legacy_name.clone()),
            },
        )?;
        let legacy_url = list_filesystem_entries(&case_path, Some(legacy.evidence_id))?
            .into_iter()
            .find(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("browser_url"))
            .expect("legacy URL record");
        let folder_id = create_bookmark_folder(&case_path, None, "Browser", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Browser URL".to_string()),
                title: Some("Legacy URL".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(legacy.evidence_id),
                entry_id: Some(legacy_url.id),
                item_order: None,
                display_name: Some(legacy_url.name.clone()),
                logical_path: Some(legacy_url.logical_path.clone()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({
                    "evidence_id": legacy.evidence_id,
                    "entry_id": legacy_url.id,
                    "logical_path": legacy_url.logical_path,
                }),
            },
        )?;

        let options = ImportBrowserArtifactsIntoEvidenceOptions {
            evidence_id: parent_evidence_id,
            history_path: profile_dir.clone(),
            max_visits: 0,
            source_profile_path: "Profile".to_string(),
            volume_index_zero_based: None,
            legacy_evidence_name: Some(legacy_name),
        };
        let first = import_browser_artifacts_into_evidence(&case_path, options.clone())?;
        let second = import_browser_artifacts_into_evidence(&case_path, options)?;
        assert_eq!(first.entries_indexed, 14);
        assert_eq!(second.entries_indexed, 14);

        let active_evidence = list_evidence(&case_path)?;
        assert_eq!(active_evidence.len(), 1);
        assert_eq!(active_evidence[0].id, parent_evidence_id);
        let parent_entries = list_filesystem_entries(&case_path, Some(parent_evidence_id))?;
        assert_eq!(parent_entries.len(), base_entries.len() + 14);
        let derived_records: Vec<_> = parent_entries
            .iter()
            .filter(|entry| entry.metadata_json["browser_derivation_key"].is_string())
            .collect();
        assert_eq!(derived_records.len(), 14);
        let derived_url = derived_records
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"].as_str() == Some("browser_url"))
            .expect("derived URL record");
        assert!(derived_url
            .logical_path
            .starts_with("/Parsed Artifacts/Browser/"));
        assert_eq!(
            derived_url.metadata_json["source_file_time_basis"].as_str(),
            Some("original_evidence_filesystem")
        );
        assert_eq!(
            derived_url.metadata_json["source_file_created_utc"].as_str(),
            Some(source_created.as_str())
        );
        assert_eq!(
            derived_url.metadata_json["source_entry_id"].as_i64(),
            Some(history_source.id)
        );
        assert!(derived_url.metadata_json["staging_file_created_utc"].is_string());
        assert!(derived_url.metadata_json["created_utc"].is_null());

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].evidence_id, Some(parent_evidence_id));
        assert!(items[0].entry_id.is_some());
        assert!(items[0]
            .logical_path
            .as_deref()
            .is_some_and(|path| path.starts_with("/Parsed Artifacts/Browser/")));
        let conn = open_existing_case(&case_path)?;
        let superseded: i64 = conn.query_row(
            "SELECT COUNT(*) FROM evidence_sources WHERE attach_status = 'superseded'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(superseded, 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn chromium_history_import_reads_pending_wal_rows() -> Result<()> {
        let case_path = unique_case_path("history-import-wal");
        create_test_case(&case_path)?;
        let history_dir = unique_temp_dir("history-import-wal-source");
        fs::create_dir_all(&history_dir)?;
        let history_path = history_dir.join("History");
        let writer = create_test_chromium_history_with_pending_wal(&history_path)?;
        assert!(
            sqlite_sidecar_path(&history_path, "-wal").is_file(),
            "test setup should leave the committed row in a WAL sidecar"
        );

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 10,
                evidence_name: Some("Chrome WAL History".to_string()),
            },
        )?;
        assert_eq!(imported.visits_indexed, 1);
        assert_eq!(imported.entries_indexed, 2);

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert!(entries.iter().any(|entry| {
            entry.metadata_json["artifact_kind"].as_str() == Some("browser_history_visit")
                && entry.metadata_json["url"].as_str() == Some("https://wal.example/recent")
        }));

        drop(writer);
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(history_dir);
        Ok(())
    }

    #[test]
    fn sqlite_browser_copy_recovers_hot_journal_without_touching_source() -> Result<()> {
        let root = unique_temp_dir("browser-hot-journal");
        let active_path = root.join("active.sqlite");
        let source_path = root.join("History");
        let active = Connection::open(&active_path)?;
        active.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA cache_size = 1;
             CREATE TABLE recovery_test(value TEXT NOT NULL);
             INSERT INTO recovery_test(value) VALUES ('committed');
             BEGIN IMMEDIATE;
             UPDATE recovery_test SET value = 'uncommitted';",
        )?;
        // Force the changed page into the active database while its rollback
        // journal still contains the committed page, then copy both files as
        // the deterministic equivalent of a process crash.
        active.cache_flush()?;
        let active_journal = sqlite_sidecar_path(&active_path, "-journal");
        assert!(active_journal.is_file());
        fs::copy(&active_path, &source_path)?;
        let source_journal = sqlite_sidecar_path(&source_path, "-journal");
        fs::copy(&active_journal, &source_journal)?;
        active.execute_batch("ROLLBACK")?;
        drop(active);

        let source_db_before = sha256_hex(&fs::read(&source_path)?);
        let source_journal_before = sha256_hex(&fs::read(&source_journal)?);
        let (recovered, _guard) = open_sqlite_copy_read_only(&source_path)?;
        assert!(!recovered.is_readonly(rusqlite::DatabaseName::Main)?);
        let value: String =
            recovered.query_row("SELECT value FROM recovery_test", [], |row| row.get(0))?;
        assert_eq!(value, "committed");
        assert_eq!(source_db_before, sha256_hex(&fs::read(&source_path)?));
        assert_eq!(
            source_journal_before,
            sha256_hex(&fs::read(&source_journal)?)
        );

        drop(recovered);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    /// Firefox 3.0-era (2008) profiles: places.sqlite has no
    /// moz_places.last_visit_date, formhistory.sqlite has only
    /// id/fieldname/value, and cookies.sqlite has no creationTime. Readers
    /// must adapt to the era schema instead of failing (found on the
    /// nps-2008-jean image, where both profiles imported zero visits).
    #[test]
    fn firefox3_era_profile_imports_visits_without_modern_columns() -> Result<()> {
        let case_path = unique_case_path("firefox3-era-import");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox3-era-source");
        fs::create_dir_all(&profile_dir)?;
        let conn = Connection::open(profile_dir.join("places.sqlite"))?;
        conn.execute_batch(
            "CREATE TABLE moz_places(
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                rev_host TEXT,
                visit_count INTEGER,
                hidden INTEGER DEFAULT 0,
                typed INTEGER DEFAULT 0,
                favicon_id INTEGER,
                frecency INTEGER DEFAULT -1
             );
             CREATE TABLE moz_historyvisits(
                id INTEGER PRIMARY KEY,
                from_visit INTEGER,
                place_id INTEGER,
                visit_date INTEGER,
                visit_type INTEGER,
                session INTEGER
             );
             CREATE TABLE moz_bookmarks(
                id INTEGER PRIMARY KEY,
                type INTEGER,
                fk INTEGER,
                parent INTEGER,
                position INTEGER,
                title TEXT,
                keyword_id INTEGER,
                folder_type TEXT,
                dateAdded INTEGER,
                lastModified INTEGER
             );
             INSERT INTO moz_places(id, url, title, rev_host, visit_count, typed, frecency)
             VALUES (1, 'http://www.example2008.com/', 'Example 2008', 'moc.8002elpmaxe.www.', 2, 1, 100),
                    (2, 'http://mail.example2008.com/inbox', 'Inbox', 'moc.8002elpmaxe.liam.', 1, 0, 50);
             INSERT INTO moz_historyvisits(id, from_visit, place_id, visit_date, visit_type, session)
             VALUES (1, 0, 1, 1210780800000000, 1, 1),
                    (2, 1, 2, 1210784400000000, 1, 1);
             INSERT INTO moz_bookmarks(id, type, fk, parent, position, title, dateAdded, lastModified)
             VALUES (1, 1, 1, 0, 0, 'Example bookmark', 1210780800000000, 1210780800000000);",
        )?;
        drop(conn);
        let conn = Connection::open(profile_dir.join("formhistory.sqlite"))?;
        conn.execute_batch(
            "CREATE TABLE moz_formhistory(
                id INTEGER PRIMARY KEY,
                fieldname TEXT NOT NULL,
                value TEXT NOT NULL
             );
             INSERT INTO moz_formhistory(id, fieldname, value)
             VALUES (1, 'searchbar-history', 'vintage search');",
        )?;
        drop(conn);
        let conn = Connection::open(profile_dir.join("cookies.sqlite"))?;
        conn.execute_batch(
            "CREATE TABLE moz_cookies(
                id INTEGER PRIMARY KEY,
                name TEXT,
                value TEXT,
                host TEXT,
                path TEXT,
                expiry INTEGER,
                lastAccessed INTEGER,
                isSecure INTEGER,
                isHttpOnly INTEGER
             );
             INSERT INTO moz_cookies(id, name, value, host, path, expiry, lastAccessed, isSecure, isHttpOnly)
             VALUES (1, 'session2008', 'cookie-secret-2008', '.example2008.com', '/', 1893456000, 1210780800000000, 0, 0);",
        )?;
        drop(conn);

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 2, "FF3-era visits must import");
        assert_eq!(imported.bookmarks_indexed, 1);
        assert!(
            imported.parse_errors.is_empty(),
            "no reader may fail on the FF3-era schema: {:?}",
            imported.parse_errors
        );
        assert_eq!(imported.status, "completed");

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_history_visit"), 2);
        assert_eq!(artifact_count(&entries, "browser_url"), 2);
        assert_eq!(artifact_count(&entries, "browser_search_term"), 1);
        assert_eq!(artifact_count(&entries, "browser_cookie"), 1);
        let cookie_json = entry_with_artifact(&entries, "browser_cookie")
            .metadata_json
            .to_string();
        assert!(cookie_json.contains("cookie-secret-2008"));
        assert_eq!(
            entry_with_artifact(&entries, "browser_cookie").metadata_json
                ["sensitive_value_present"]
                .as_bool(),
            Some(true)
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox3_downloads_sqlite_imports_known_answer() -> Result<()> {
        let case_path = unique_case_path("firefox3-downloads-known-answer");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox3-downloads-known-answer-source");
        create_test_empty_firefox_places(&profile_dir)?;
        create_test_firefox3_downloads(&profile_dir.join("downloads.sqlite"), true)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 0);
        assert_eq!(imported.entries_indexed, 1);
        assert!(
            imported.parse_errors.is_empty(),
            "FF3 downloads.sqlite must parse without errors: {:?}",
            imported.parse_errors
        );

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_download"), 1);
        let download = entry_with_artifact(&entries, "browser_download");
        assert_eq!(
            download.logical_path,
            "/Browser Activities/Downloads/downloads-sqlite-1-install_flash_player.exe.record"
        );
        assert_eq!(download.name, "install_flash_player.exe");
        assert_eq!(download.metadata_json["download_id"].as_i64(), Some(1));
        assert_eq!(
            download.metadata_json["file_name"].as_str(),
            Some("install_flash_player.exe")
        );
        assert_eq!(
            download.metadata_json["source_url"].as_str(),
            Some(
                "http://fpdownload.macromedia.com/get/flashplayer/current/install_flash_player.exe"
            )
        );
        assert_eq!(
            download.metadata_json["target_uri"].as_str(),
            Some(
                "file:///C:/Documents%20and%20Settings/Administrator/Desktop/install_flash_player.exe"
            )
        );
        assert_eq!(download.metadata_json["temp_path"].as_str(), Some(""));
        assert_eq!(
            download.metadata_json["referrer"].as_str(),
            Some(
                "http://www.adobe.com/shockwave/download/download.cgi?P1_Prod_Version=ShockwaveFlash"
            )
        );
        assert_eq!(
            download.metadata_json["mime_type"].as_str(),
            Some("application/octet-stream")
        );
        assert_eq!(
            download.metadata_json["curr_bytes"].as_i64(),
            Some(1_495_112)
        );
        assert_eq!(
            download.metadata_json["max_bytes"].as_i64(),
            Some(1_495_112)
        );
        assert_eq!(download.metadata_json["state"].as_i64(), Some(1));
        assert_eq!(
            download.metadata_json["state_label"].as_str(),
            Some("finished")
        );
        assert_eq!(
            download.metadata_json["host"].as_str(),
            Some("fpdownload.macromedia.com")
        );
        assert_eq!(
            download.metadata_json["start_time_prtime"].as_i64(),
            Some(1_210_744_064_453_125)
        );
        assert_eq!(
            download.metadata_json["start_time_utc"].as_str(),
            Some("2008-05-14T05:47:44.453125+00:00")
        );
        assert_eq!(
            download.metadata_json["end_time_prtime"].as_i64(),
            Some(1_210_744_066_203_125)
        );
        assert_eq!(
            download.metadata_json["end_time_utc"].as_str(),
            Some("2008-05-14T05:47:46.203125+00:00")
        );
        assert_eq!(
            download.metadata_json["source_artifact"].as_str(),
            Some("downloads.sqlite")
        );
        assert!(download.metadata_json["source_artifact_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("downloads.sqlite")));
        assert_eq!(
            download.metadata_json["category_main"].as_str(),
            Some("Web Activity")
        );
        assert_eq!(
            download.metadata_json["category_sub"].as_str(),
            Some("Downloads")
        );
        for key in [
            "created_utc",
            "modified_utc",
            "accessed_utc",
            "mft_modified_utc",
        ] {
            assert!(
                download.metadata_json[key].is_null(),
                "artifact event times must not populate generic MACB field {key}"
            );
        }

        let conn = open_existing_case(&case_path)?;
        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![imported.job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        assert!(parameters["downloads_file"]
            .as_str()
            .is_some_and(|path| path.ends_with("downloads.sqlite")));
        drop(conn);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_downloads_sqlite_empty_table_is_not_an_error() -> Result<()> {
        let case_path = unique_case_path("firefox-downloads-empty");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-downloads-empty-source");
        create_test_empty_firefox_places(&profile_dir)?;
        create_test_firefox3_downloads(&profile_dir.join("downloads.sqlite"), false)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.entries_indexed, 0);
        assert!(imported.parse_errors.is_empty());
        assert!(list_filesystem_entries(&case_path, Some(imported.evidence_id))?.is_empty());

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_downloads_sqlite_missing_file_and_table_are_not_errors() -> Result<()> {
        let case_path = unique_case_path("firefox-downloads-missing");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-downloads-missing-source");
        create_test_empty_firefox_places(&profile_dir)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.entries_indexed, 0);
        assert!(imported.parse_errors.is_empty());

        let downloads_path = profile_dir.join("downloads.sqlite");
        Connection::open(&downloads_path)?
            .execute_batch("CREATE TABLE unrelated(id INTEGER PRIMARY KEY);")?;
        let mut emit = |_record: BrowserActivityRecord| Ok(());
        assert_eq!(
            stream_firefox_downloads_sqlite_records(&downloads_path, usize::MAX, &mut emit)?,
            0
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_downloads_sqlite_failure_is_disclosed_not_swallowed() -> Result<()> {
        let case_path = unique_case_path("firefox-downloads-error-disclosure");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-downloads-error-source");
        create_test_empty_firefox_places(&profile_dir)?;
        fs::write(
            profile_dir.join("downloads.sqlite"),
            b"not a sqlite database",
        )?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.entries_indexed, 0);
        assert!(imported
            .parse_errors
            .iter()
            .any(|error| error.starts_with("downloads (downloads.sqlite):")));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_download_readers_coexist_without_logical_path_collision() -> Result<()> {
        let case_path = unique_case_path("firefox-downloads-coexist");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-downloads-coexist-source");
        create_test_empty_firefox_places(&profile_dir)?;
        let places = Connection::open(profile_dir.join("places.sqlite"))?;
        places.execute_batch(
            "CREATE TABLE moz_anno_attributes(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
             );
             CREATE TABLE moz_annos(
                id INTEGER PRIMARY KEY,
                place_id INTEGER NOT NULL,
                anno_attribute_id INTEGER NOT NULL,
                content TEXT,
                dateAdded INTEGER,
                lastModified INTEGER
             );
             INSERT INTO moz_places(id, url, title)
             VALUES (1,
                'http://fpdownload.macromedia.com/get/flashplayer/current/install_flash_player.exe',
                'Flash Player');
             INSERT INTO moz_anno_attributes(id, name)
             VALUES (1, 'downloads/destinationFileURI');
             INSERT INTO moz_annos(
                id, place_id, anno_attribute_id, content, dateAdded, lastModified
             ) VALUES (
                1, 1, 1,
                'file:///C:/Documents%20and%20Settings/Administrator/Desktop/install_flash_player.exe',
                1210744064453125, 1210744066203125
             );",
        )?;
        drop(places);
        create_test_firefox3_downloads(&profile_dir.join("downloads.sqlite"), true)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        let downloads = entries
            .iter()
            .filter(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("browser_download")
            })
            .collect::<Vec<_>>();
        assert_eq!(downloads.len(), 2);
        let logical_paths = downloads
            .iter()
            .map(|entry| entry.logical_path.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(logical_paths.len(), 2);
        assert!(logical_paths
            .contains("/Browser Activities/Downloads/1-install_flash_player.exe.record"));
        assert!(logical_paths.contains(
            "/Browser Activities/Downloads/downloads-sqlite-1-install_flash_player.exe.record"
        ));
        assert!(downloads.iter().any(|entry| {
            entry.metadata_json["annotation_id"].as_i64() == Some(1)
                && entry.metadata_json["source_artifact"].as_str() == Some("places.sqlite")
        }));
        assert!(downloads.iter().any(|entry| {
            entry.metadata_json["download_id"].as_i64() == Some(1)
                && entry.metadata_json["source_artifact"].as_str() == Some("downloads.sqlite")
        }));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_downloads_sqlite_derived_provenance_uses_original_source_entry() -> Result<()> {
        let case_path = unique_case_path("firefox-downloads-derived-provenance");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("firefox-downloads-derived-provenance-source");
        let profile_dir = evidence_dir.join("Profile");
        create_test_empty_firefox_places(&profile_dir)?;
        create_test_firefox3_downloads(&profile_dir.join("downloads.sqlite"), true)?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;
        let source_entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let downloads_source = source_entries
            .iter()
            .find(|entry| entry.name == "downloads.sqlite")
            .expect("indexed downloads.sqlite source entry");
        let expected_modified = downloads_source.metadata_json["modified_utc"]
            .as_str()
            .expect("indexed downloads.sqlite modified time")
            .to_string();
        let downloads_source_id = downloads_source.id;

        let imported = import_browser_artifacts_into_evidence(
            &case_path,
            ImportBrowserArtifactsIntoEvidenceOptions {
                evidence_id,
                history_path: profile_dir.clone(),
                max_visits: 0,
                source_profile_path: "Profile".to_string(),
                volume_index_zero_based: None,
                legacy_evidence_name: None,
            },
        )?;
        assert!(imported.parse_errors.is_empty());
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        let download = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("browser_download")
                    && entry.metadata_json["download_id"].as_i64() == Some(1)
            })
            .expect("derived downloads.sqlite record");
        assert_eq!(
            download.metadata_json["source_entry_id"].as_i64(),
            Some(downloads_source_id)
        );
        assert_eq!(
            download.metadata_json["source_file_time_basis"].as_str(),
            Some("original_evidence_filesystem")
        );
        assert_eq!(
            download.metadata_json["source_file_modified_utc"].as_str(),
            Some(expected_modified.as_str())
        );
        assert!(download.metadata_json["source_artifact_path_exact"]
            .as_str()
            .is_some_and(|path| path
                .replace('\\', "/")
                .ends_with("Profile/downloads.sqlite")));
        assert!(download.metadata_json["staging_file_modified_utc"].is_string());
        for key in [
            "created_utc",
            "modified_utc",
            "accessed_utc",
            "mft_modified_utc",
        ] {
            assert!(download.metadata_json[key].is_null());
        }

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    /// A reader failure must be disclosed on the import instead of being
    /// silently presented as an artifact-free profile.
    #[test]
    fn firefox_reader_failure_is_disclosed_not_swallowed() -> Result<()> {
        let case_path = unique_case_path("firefox-parse-error-disclosure");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-parse-error-source");
        fs::create_dir_all(&profile_dir)?;
        fs::write(profile_dir.join("places.sqlite"), b"not a sqlite database")?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 0,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 0);
        assert!(
            !imported.parse_errors.is_empty(),
            "an unreadable places.sqlite must be disclosed as parse errors"
        );
        assert!(imported
            .parse_errors
            .iter()
            .any(|error| error.starts_with("history visits:")));
        assert!(imported.truncated);
        assert_eq!(imported.status, "truncated");
        let conn = open_existing_case(&case_path)?;
        let (job_status, job_error): (String, Option<String>) = conn.query_row(
            "SELECT status, error FROM evidence_jobs WHERE id = ?1",
            [imported.job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(job_status, "truncated");
        assert!(job_error
            .as_deref()
            .is_some_and(|error| error.contains("could not be parsed")));
        drop(conn);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn firefox_history_import_reads_profile_artifacts_and_truncates() -> Result<()> {
        let case_path = unique_case_path("firefox-history-import");
        create_test_case(&case_path)?;
        let profile_dir = unique_temp_dir("firefox-history-source");
        create_test_firefox_profile(&profile_dir)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 10,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 2);
        assert_eq!(imported.bookmarks_indexed, 2);
        assert_eq!(imported.preferences_indexed, 0);
        assert_eq!(imported.entries_indexed, 9);
        assert_eq!(imported.status, "completed");

        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence[0].source_kind, "browser_history");
        assert!(evidence[0].display_name.starts_with("Firefox History - "));

        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_history_visit"), 2);
        assert_eq!(artifact_count(&entries, "browser_url"), 2);
        assert_eq!(artifact_count(&entries, "browser_bookmark"), 2);
        assert_eq!(artifact_count(&entries, "browser_search_term"), 1);
        assert_eq!(artifact_count(&entries, "browser_cookie"), 1);
        assert_eq!(artifact_count(&entries, "browser_login"), 1);
        assert!(entries
            .iter()
            .all(|entry| { entry.metadata_json["browser_family"].as_str() == Some("firefox") }));

        let visit = entry_with_artifact(&entries, "browser_history_visit");
        assert_eq!(
            visit.metadata_json["category_main"].as_str(),
            Some("Web Activity")
        );
        assert_eq!(
            visit.metadata_json["visit_time_utc"].as_str(),
            Some("2009-12-11T00:00:00+00:00")
        );
        let login = entry_with_artifact(&entries, "browser_login");
        assert_eq!(
            login.metadata_json["category_main"].as_str(),
            Some("Accounts and Identity")
        );
        let login_json = login.metadata_json.to_string();
        assert!(login_json.contains("encrypted-user"));
        assert!(login_json.contains("encrypted-pass"));
        assert_eq!(
            login.metadata_json["sensitive_value_present"].as_bool(),
            Some(true)
        );
        let cookie_json = entry_with_artifact(&entries, "browser_cookie")
            .metadata_json
            .to_string();
        assert!(cookie_json.contains("cookie-secret"));
        assert_eq!(
            entry_with_artifact(&entries, "browser_cookie").metadata_json
                ["sensitive_value_present"]
                .as_bool(),
            Some(true)
        );

        let truncated = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: profile_dir.clone(),
                max_visits: 1,
                evidence_name: None,
            },
        )?;
        assert_eq!(truncated.evidence_id, imported.evidence_id);
        assert_eq!(truncated.visits_indexed, 1);
        assert!(truncated.truncated);
        assert_eq!(truncated.status, "truncated");
        let truncated_entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(
            artifact_count(&truncated_entries, "browser_history_visit"),
            1
        );
        assert_eq!(artifact_count(&truncated_entries, "browser_url"), 1);
        assert_eq!(artifact_count(&truncated_entries, "browser_bookmark"), 1);
        assert_eq!(artifact_count(&truncated_entries, "browser_search_term"), 1);
        assert_eq!(artifact_count(&truncated_entries, "browser_cookie"), 1);
        assert_eq!(artifact_count(&truncated_entries, "browser_login"), 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn safari_history_import_reads_visits_urls_and_core_data_time() -> Result<()> {
        let case_path = unique_case_path("safari-history-import");
        create_test_case(&case_path)?;
        let history_dir = unique_temp_dir("safari-history-source");
        let history_path = history_dir.join("History.db");
        create_test_safari_history(&history_path)?;

        let imported = import_browser_history(
            &case_path,
            ImportBrowserHistoryOptions {
                history_path: history_path.clone(),
                max_visits: 10,
                evidence_name: None,
            },
        )?;
        assert_eq!(imported.visits_indexed, 2);
        assert_eq!(imported.bookmarks_indexed, 0);
        assert_eq!(imported.entries_indexed, 4);

        let evidence = list_evidence(&case_path)?;
        assert!(evidence[0].display_name.starts_with("Safari History - "));
        let entries = list_filesystem_entries(&case_path, Some(imported.evidence_id))?;
        assert_eq!(artifact_count(&entries, "browser_history_visit"), 2);
        assert_eq!(artifact_count(&entries, "browser_url"), 2);
        assert!(entries
            .iter()
            .all(|entry| { entry.metadata_json["browser_family"].as_str() == Some("safari") }));
        let known_visit = entries
            .iter()
            .find(|entry| {
                entry.metadata_json["artifact_kind"].as_str() == Some("browser_history_visit")
                    && entry.metadata_json["url"].as_str() == Some("https://apple.example/history")
            })
            .expect("known Safari visit should be imported");
        assert_eq!(
            known_visit.metadata_json["visit_time_utc"].as_str(),
            Some("2009-12-11T00:00:00+00:00")
        );
        assert_eq!(
            known_visit.metadata_json["category_main"].as_str(),
            Some("Web Activity")
        );

        let conn = open_existing_case(&case_path)?;
        let parameters_json: String = conn.query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![imported.job_id],
            |row| row.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters_json)?;
        assert_eq!(
            parameters["unsupported_artifacts"][0].as_str(),
            Some("bookmarks_plist")
        );
        assert_eq!(
            parameters["unsupported_artifacts"][1].as_str(),
            Some("downloads_plist")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(history_dir);
        Ok(())
    }

    #[test]
    fn browser_family_detection_handles_names_sniffing_and_ambiguity() -> Result<()> {
        let root = unique_temp_dir("browser-detection");
        let chromium_file = root.join("HISTORY");
        let firefox_file = root.join("PLACES.SQLITE");
        let safari_file = root.join("History.DB");
        fs::write(&chromium_file, b"")?;
        fs::write(&firefox_file, b"")?;
        fs::write(&safari_file, b"")?;
        assert_eq!(
            detect_browser_family(&chromium_file)?,
            BrowserFamily::Chromium
        );
        assert_eq!(
            detect_browser_family(&firefox_file)?,
            BrowserFamily::Firefox
        );
        assert_eq!(detect_browser_family(&safari_file)?, BrowserFamily::Safari);

        let sniff_firefox = root.join("unknown-firefox.sqlite");
        Connection::open(&sniff_firefox)?
            .execute_batch("CREATE TABLE moz_places(id INTEGER PRIMARY KEY);")?;
        assert_eq!(
            detect_browser_family(&sniff_firefox)?,
            BrowserFamily::Firefox
        );
        let sniff_safari = root.join("unknown-safari.sqlite");
        Connection::open(&sniff_safari)?.execute_batch(
            "CREATE TABLE history_items(id INTEGER PRIMARY KEY);
             CREATE TABLE history_visits(id INTEGER PRIMARY KEY);",
        )?;
        assert_eq!(detect_browser_family(&sniff_safari)?, BrowserFamily::Safari);
        let sniff_safari_single_table = root.join("unknown-safari-single-table.sqlite");
        Connection::open(&sniff_safari_single_table)?
            .execute_batch("CREATE TABLE history_visits(id INTEGER PRIMARY KEY);")?;
        assert_eq!(
            detect_browser_database(&sniff_safari_single_table)?,
            Some(BrowserFamily::Safari)
        );
        let sniff_chromium = root.join("unknown-chromium.sqlite");
        Connection::open(&sniff_chromium)?.execute_batch(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY);
             CREATE TABLE visits(id INTEGER PRIMARY KEY);",
        )?;
        assert_eq!(
            detect_browser_family(&sniff_chromium)?,
            BrowserFamily::Chromium
        );

        let ambiguous_dir = root.join("ambiguous");
        fs::create_dir_all(&ambiguous_dir)?;
        fs::write(ambiguous_dir.join("History"), b"")?;
        fs::write(ambiguous_dir.join("places.sqlite"), b"")?;
        let err = detect_browser_family(&ambiguous_dir)
            .expect_err("multiple browser databases in one directory should be ambiguous")
            .to_string();
        assert!(err.contains("ambiguous browser profile directory"));
        assert!(err.contains("point at the specific DB file"));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn evidence_process_respects_entry_limit() -> Result<()> {
        let case_path = unique_case_path("process-limit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("process-limit-source");
        fs::write(evidence_dir.join("a.txt"), b"a")?;
        fs::write(evidence_dir.join("b.txt"), b"b")?;

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let processed = process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 1,
            },
        )?;
        assert_eq!(processed.status, "truncated");
        assert!(processed.truncated);
        assert_eq!(processed.entries_indexed, 1);
        assert_eq!(filesystem_entry_count(&case_path)?, 1);
        assert!(list_evidence(&case_path)?[0].indexed_at.is_none());

        // The fixture has two independently created files, so a one-entry
        // result is known to be partial without asking the implementation to
        // interpret its own output. Capture the indexed entry as a finding and
        // require the job scope to follow it into report provenance.
        let entries = list_filesystem_entries(&case_path, Some(evidence_id))?;
        assert_eq!(entries.len(), 1);
        let bookmark_id = create_test_bookmark(&case_path)?;
        let item = add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(entries[0].id),
                item_order: None,
                display_name: None,
                logical_path: None,
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({}),
            },
        )?;
        assert_eq!(item.item_ref_json["index_job_status"], "truncated");
        assert_eq!(item.item_ref_json["index_requested_entry_limit"], 1);
        assert_eq!(item.item_ref_json["index_entries_indexed"], 1);
        assert!(item.item_ref_json["index_truncation_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("entry limit reached")));

        let report = report_data(&case_path)?;
        let source = &report.evidence[0];
        assert_eq!(source.latest_process_job_id, Some(processed.job_id));
        assert_eq!(
            source.latest_process_job_type.as_deref(),
            Some("filesystem_index")
        );
        assert_eq!(
            source.latest_process_job_status.as_deref(),
            Some("truncated")
        );
        assert_eq!(source.requested_entry_limit, Some(1));
        assert_eq!(source.latest_process_entries_indexed, Some(1));
        assert!(source
            .processing_truncation_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("entry limit reached")));
        assert!(source.processing_coverage.contains("PARTIAL INDEXING ONLY"));
        assert!(source
            .processing_coverage
            .contains("do not represent full source coverage"));

        let html = render_report_html(&report);
        assert!(html.contains("Latest processing status"));
        assert!(html.contains("Requested limit"));
        assert!(html.contains("Latest job indexed entries"));
        assert!(html.contains("PARTIAL INDEXING ONLY"));
        assert!(html.contains("Processing Coverage Warning"));
        assert!(html.contains("contains findings derived from truncated"));
        assert!(html.contains("entry limit reached"));
        assert!(!html.contains("Complete indexing job"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn bookmark_type_parse_accepts_canonical_types() -> Result<()> {
        let cases = [
            ("notable_file", BookmarkType::NotableFile),
            ("file_group", BookmarkType::FileGroup),
            ("highlighted_data", BookmarkType::HighlightedData),
            ("folder_info", BookmarkType::FolderInfo),
            ("email", BookmarkType::Email),
            ("record", BookmarkType::Record),
            ("FILE_GROUP", BookmarkType::FileGroup),
        ];

        for (input, expected) in cases {
            assert_eq!(BookmarkType::parse(input)?, expected);
        }
        assert!(BookmarkType::parse("tag").is_err());
        Ok(())
    }

    #[test]
    fn bookmark_create_and_list_round_trip() -> Result<()> {
        let case_path = unique_case_path("bookmark-round-trip");
        create_test_case(&case_path)?;
        let folder_id =
            create_bookmark_folder(&case_path, None, "Findings", Some("Report-ready"), true)?;

        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Text".to_string()),
                title: Some("  Suspicious phrase  ".to_string()),
                examiner_comment: Some("  Confirmed by examiner  ".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({ "evidence_id": 1 }),
                content_ref_json: serde_json::json!({ "offset": 128, "length": 16 }),
            },
        )?;
        assert_eq!(bookmark_id, 1);

        let folders = list_bookmark_folders(&case_path)?;
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, folder_id);
        assert!(!folders[0].created_at.is_empty());
        assert!(!folders[0].updated_at.is_empty());

        let bookmarks = list_bookmarks(&case_path)?;
        assert_eq!(bookmarks.len(), 1);
        let bookmark = &bookmarks[0];
        assert_eq!(bookmark.folder_id, folder_id);
        assert_eq!(bookmark.bookmark_type, "highlighted_data");
        assert_eq!(bookmark.data_type.as_deref(), Some("Text"));
        assert_eq!(bookmark.title.as_deref(), Some("Suspicious phrase"));
        assert_eq!(
            bookmark.examiner_comment.as_deref(),
            Some("Confirmed by examiner")
        );
        assert!(bookmark.in_report);
        assert_eq!(bookmark.source_ref_json["evidence_id"], 1);
        assert_eq!(bookmark.content_ref_json["offset"], 128);

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_create_rejects_missing_folder() -> Result<()> {
        let case_path = unique_case_path("bookmark-missing-folder");
        create_test_case(&case_path)?;

        let err = create_bookmark(&case_path, test_bookmark_options(999))
            .expect_err("missing bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder does not exist"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_create_rejects_non_object_json_refs() -> Result<()> {
        let case_path = unique_case_path("bookmark-json");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Findings", None, true)?;
        let mut options = test_bookmark_options(folder_id);
        options.source_ref_json = serde_json::json!(["not", "an", "object"]);

        let err = create_bookmark(&case_path, options)
            .expect_err("non-object source_ref_json should be rejected")
            .to_string();
        assert!(err.contains("source_ref_json"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_folder_rejects_duplicate_root_name() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-duplicate-root");
        create_test_case(&case_path)?;
        create_bookmark_folder(&case_path, None, "Findings", None, true)?;

        let err = create_bookmark_folder(&case_path, None, "Findings", None, true)
            .expect_err("duplicate root bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_folder_rejects_duplicate_child_name() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-duplicate-child");
        create_test_case(&case_path)?;
        let parent_id = create_bookmark_folder(&case_path, None, "Parent", None, true)?;
        create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)?;

        let err = create_bookmark_folder(&case_path, Some(parent_id), "Child", None, true)
            .expect_err("duplicate child bookmark folder should be rejected")
            .to_string();
        assert!(err.contains("bookmark folder already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_and_list_round_trip() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-round-trip");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;

        let item = add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("  selected bytes  ".to_string()),
                logical_path: Some("/logical/path.txt".to_string()),
                selection_offset: Some(32),
                selection_length: Some(12),
                data_preview: Some("  preview text  ".to_string()),
                item_ref_json: serde_json::json!({ "artifact": "text", "confidence": 1 }),
            },
        )?;
        assert_eq!(item.id, 1);
        assert_eq!(item.bookmark_id, bookmark_id);
        assert_eq!(item.item_order, 10);

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].bookmark_id, bookmark_id);
        assert_eq!(items[0].item_order, 10);
        assert_eq!(items[0].display_name.as_deref(), Some("selected bytes"));
        assert_eq!(items[0].logical_path.as_deref(), Some("/logical/path.txt"));
        assert_eq!(items[0].selection_offset, Some(32));
        assert_eq!(items[0].selection_length, Some(12));
        assert_eq!(items[0].data_preview.as_deref(), Some("preview text"));
        assert_eq!(items[0].item_ref_json["artifact"].as_str(), Some("text"));
        assert!(!items[0].created_at.is_empty());

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_auto_order_and_all_items_list() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-all");
        create_test_case(&case_path)?;
        let first_bookmark_id = create_test_bookmark(&case_path)?;
        let second_folder_id = create_bookmark_folder(&case_path, None, "Second", None, true)?;
        let second_bookmark_id =
            create_bookmark(&case_path, test_bookmark_options(second_folder_id))?;

        add_bookmark_item(&case_path, test_bookmark_item_options(first_bookmark_id))?;
        add_bookmark_item(&case_path, test_bookmark_item_options(first_bookmark_id))?;
        add_bookmark_item(&case_path, test_bookmark_item_options(second_bookmark_id))?;

        let first_items = list_bookmark_items(&case_path, Some(first_bookmark_id))?;
        assert_eq!(first_items.len(), 2);
        assert_eq!(first_items[0].item_order, 10);
        assert_eq!(first_items[1].item_order, 20);

        let all_items = list_bookmark_items(&case_path, None)?;
        assert_eq!(all_items.len(), 3);

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_delete_removes_items_and_records_audit() -> Result<()> {
        let case_path = unique_case_path("bookmark-delete");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        add_bookmark_item(&case_path, test_bookmark_item_options(bookmark_id))?;
        add_bookmark_item(&case_path, test_bookmark_item_options(bookmark_id))?;

        let removed = remove_bookmark(&case_path, bookmark_id)?;
        assert_eq!(removed.bookmark_id, bookmark_id);
        assert_eq!(removed.removed_items, 2);
        assert!(list_bookmarks(&case_path)?.is_empty());
        assert!(list_bookmark_items(&case_path, None)?.is_empty());

        let conn = open_existing_case(&case_path)?;
        let event_type: String = conn.query_row(
            "SELECT event_type FROM audit_events WHERE object_type = 'bookmark' AND object_id = ?1 ORDER BY id DESC LIMIT 1",
            params![bookmark_id],
            |row| row.get(0),
        )?;
        assert_eq!(event_type, "bookmark.delete");

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_delete_removes_only_selected_item() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-delete");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let first = add_bookmark_item(&case_path, test_bookmark_item_options(bookmark_id))?;
        let second = add_bookmark_item(&case_path, test_bookmark_item_options(bookmark_id))?;

        let removed = remove_bookmark_item(&case_path, first.id)?;
        assert_eq!(removed.item_id, first.id);
        assert_eq!(removed.bookmark_id, bookmark_id);
        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, second.id);
        assert_eq!(list_bookmarks(&case_path)?.len(), 1);

        let conn = open_existing_case(&case_path)?;
        let event_type: String = conn.query_row(
            "SELECT event_type FROM audit_events WHERE object_type = 'bookmark_item' AND object_id = ?1 ORDER BY id DESC LIMIT 1",
            params![first.id],
            |row| row.get(0),
        )?;
        assert_eq!(event_type, "bookmark.item.delete");

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_duplicate_explicit_order() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-duplicate-order");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let mut first = test_bookmark_item_options(bookmark_id);
        first.item_order = Some(5);
        add_bookmark_item(&case_path, first)?;

        let mut second = test_bookmark_item_options(bookmark_id);
        second.item_order = Some(5);
        let err = add_bookmark_item(&case_path, second)
            .expect_err("duplicate item order should be rejected")
            .to_string();
        assert!(err.contains("bookmark item order already exists"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_missing_bookmark() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-missing");
        create_test_case(&case_path)?;

        let err = add_bookmark_item(&case_path, test_bookmark_item_options(999))
            .expect_err("missing bookmark should be rejected")
            .to_string();
        assert!(err.contains("bookmark does not exist"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_entry_from_other_evidence() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-entry-evidence");
        create_test_case(&case_path)?;
        let first_source = unique_temp_dir("bookmark-entry-evidence-a");
        let second_source = unique_temp_dir("bookmark-entry-evidence-b");
        fs::write(first_source.join("a.txt"), b"a")?;
        fs::write(second_source.join("b.txt"), b"b")?;
        let first_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: first_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let second_evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: second_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/a.txt', 'a.txt', 'file')",
            rusqlite::params![case_id, first_evidence_id],
        )?;
        let entry_id = conn.last_insert_rowid();

        let mut options = test_bookmark_item_options(bookmark_id);
        options.evidence_id = Some(second_evidence_id);
        options.entry_id = Some(entry_id);
        let err = add_bookmark_item(&case_path, options)
            .expect_err("entry tied to another evidence source should be rejected")
            .to_string();
        assert!(err.contains("belongs to evidence source"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(first_source);
        let _ = fs::remove_dir_all(second_source);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_backfills_evidence_from_entry() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-entry-backfill");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-entry-backfill");
        fs::write(evidence_source.join("a.txt"), b"a")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/a.txt', 'a.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        let entry_id = conn.last_insert_rowid();

        let mut options = test_bookmark_item_options(bookmark_id);
        options.entry_id = Some(entry_id);
        let item = add_bookmark_item(&case_path, options)?;
        assert_eq!(item.evidence_id, Some(evidence_id));
        assert_eq!(item.entry_id, Some(entry_id));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_backfills_display_and_reference_from_entry_for_report() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-report-backfill");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-report-backfill");
        fs::create_dir_all(&evidence_source)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let metadata = serde_json::json!({
            "artifact_kind": "browser_login",
            "browser_family": "chromium",
            "host": "ebank.example.com",
            "username": "jdoe",
            "search_text": "must not leak into the report reference"
        });
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, '/Browser Activities/Logins/ebank.example.com/jdoe.record',
                       'jdoe @ ebank.example.com', 'record', ?3)",
            rusqlite::params![case_id, evidence_id, metadata.to_string()],
        )?;
        let entry_id = conn.last_insert_rowid();
        drop(conn);

        // Only entry_id supplied - the CLI's only bookmarking path, with no client-side
        // entry cache to draw display_name/logical_path/item_ref_json from.
        let mut options = test_bookmark_item_options(bookmark_id);
        options.entry_id = Some(entry_id);
        let item = add_bookmark_item(&case_path, options)?;
        assert_eq!(
            item.display_name.as_deref(),
            Some("jdoe @ ebank.example.com")
        );
        assert_eq!(
            item.logical_path.as_deref(),
            Some("/Browser Activities/Logins/ebank.example.com/jdoe.record")
        );
        assert_eq!(
            item.item_ref_json["kind"],
            serde_json::json!("browser_activity")
        );
        assert_eq!(
            item.item_ref_json["activity_kind"],
            serde_json::json!("browser_login")
        );
        assert_eq!(
            item.item_ref_json["host"],
            serde_json::json!("ebank.example.com")
        );
        assert!(item.item_ref_json.get("search_text").is_none());

        let report = report_data(&case_path)?;
        let html = render_report_html(&report);
        assert!(html.contains("jdoe @ ebank.example.com"));
        assert!(html.contains("ebank.example.com"));
        assert!(!html.contains("must not leak"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bulk_add_bookmark_items_inserts_all_in_one_transaction_and_skips_missing_entries(
    ) -> Result<()> {
        let case_path = unique_case_path("bookmark-bulk-add");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-bulk-add");
        fs::create_dir_all(&evidence_source)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let mut entry_ids = Vec::new();
        for index in 0..25 {
            conn.execute(
                "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
                 VALUES (?1, ?2, ?3, ?4, 'file')",
                rusqlite::params![
                    case_id,
                    evidence_id,
                    format!("/bulk-{index}.txt"),
                    format!("bulk-{index}.txt")
                ],
            )?;
            entry_ids.push(conn.last_insert_rowid());
        }
        let missing_entry_id = entry_ids.iter().max().copied().unwrap_or(0) + 1000;
        drop(conn);

        let mut request_ids = entry_ids.clone();
        request_ids.push(missing_entry_id);
        let result = bulk_add_bookmark_items(&case_path, bookmark_id, &request_ids)?;
        assert_eq!(result.items_added, 25);
        assert_eq!(result.skipped_entry_ids, vec![missing_entry_id]);

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 25);
        assert_eq!(items[0].item_order, 10);
        assert_eq!(items[24].item_order, 250);
        assert_eq!(items[0].display_name.as_deref(), Some("bulk-0.txt"));
        assert_eq!(items[0].logical_path.as_deref(), Some("/bulk-0.txt"));
        assert_eq!(
            items[0].item_ref_json["kind"],
            serde_json::json!("category_entry")
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_indexed_folder_recursive_bulk_adds_descendant_files_only() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-recursive-indexed");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-folder-recursive-indexed");
        fs::create_dir_all(&evidence_source)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Target', 'Target', 'directory')",
            rusqlite::params![case_id, evidence_id],
        )?;
        for index in 0..3 {
            conn.execute(
                "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
                 VALUES (?1, ?2, ?3, ?4, 'file')",
                rusqlite::params![
                    case_id,
                    evidence_id,
                    format!("/Target/file-{index}.txt"),
                    format!("file-{index}.txt")
                ],
            )?;
        }
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Target/Sub', 'Sub', 'directory')",
            rusqlite::params![case_id, evidence_id],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Target/Sub/nested.txt', 'nested.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        // A file outside /Target that must NOT be swept up, and one whose path
        // merely starts with the same prefix text (not an actual descendant).
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/outside.txt', 'outside.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Target2/decoy.txt', 'decoy.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        drop(conn);

        let result = bookmark_indexed_folder_recursive(
            &case_path,
            bookmark_id,
            evidence_id,
            "/Target",
            RECURSIVE_FOLDER_BOOKMARK_LIMIT,
        )?;
        assert_eq!(result.items_added, 4);
        assert_eq!(result.total_candidates, 4);
        assert!(!result.truncated);

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 4);
        let paths: Vec<_> = items
            .iter()
            .filter_map(|item| item.logical_path.clone())
            .collect();
        assert!(paths.contains(&"/Target/file-0.txt".to_string()));
        assert!(paths.contains(&"/Target/Sub/nested.txt".to_string()));
        assert!(!paths.iter().any(|path| path == "/outside.txt"));
        assert!(!paths.iter().any(|path| path == "/Target2/decoy.txt"));
        assert!(!paths.iter().any(|path| path == "/Target"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_indexed_folder_recursive_rejects_nonexistent_path_but_allows_root() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-recursive-indexed-missing");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-folder-recursive-indexed-missing");
        fs::create_dir_all(&evidence_source)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Real', 'Real', 'directory')",
            rusqlite::params![case_id, evidence_id],
        )?;
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, logical_path, name, entry_kind)
             VALUES (?1, ?2, '/Real/file.txt', 'file.txt', 'file')",
            rusqlite::params![case_id, evidence_id],
        )?;
        drop(conn);

        // A folder path that was never indexed must error instead of silently
        // producing an empty bookmark (previously returned items_added: 0 with
        // no signal that the path was bogus rather than genuinely empty).
        let missing = bookmark_indexed_folder_recursive(
            &case_path,
            bookmark_id,
            evidence_id,
            "/Real/does-not-exist",
            RECURSIVE_FOLDER_BOOKMARK_LIMIT,
        );
        assert!(missing.is_err());
        assert!(missing
            .unwrap_err()
            .to_string()
            .contains("directory not found"));

        // The whole-evidence root ("/") has no directory row of its own and
        // must remain valid even when it is genuinely empty of un-nested files.
        let root = bookmark_indexed_folder_recursive(
            &case_path,
            bookmark_id,
            evidence_id,
            "/",
            RECURSIVE_FOLDER_BOOKMARK_LIMIT,
        )?;
        assert_eq!(root.items_added, 1);
        assert_eq!(root.total_candidates, 1);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_live_folder_recursive_walks_local_folder_tree_without_indexing() -> Result<()> {
        let case_path = unique_case_path("bookmark-folder-recursive-live");
        create_test_case(&case_path)?;
        let evidence_source = unique_temp_dir("bookmark-folder-recursive-live");
        fs::create_dir_all(evidence_source.join("Sub"))?;
        fs::write(evidence_source.join("a.txt"), b"hello")?;
        fs::write(evidence_source.join("b.txt"), b"world!!")?;
        fs::write(evidence_source.join("Sub").join("c.txt"), b"nested")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_source.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let bookmark_id = create_test_bookmark(&case_path)?;

        let limited_listing = list_local_tree_files(&case_path, evidence_id, "/", 1)?;
        assert_eq!(limited_listing.files.len(), 1);
        assert_eq!(limited_listing.file_limit, Some(1));
        assert!(limited_listing.file_limit_reached);
        assert!(limited_listing.truncated);

        let listing = list_local_tree_files(
            &case_path,
            evidence_id,
            "/",
            RECURSIVE_FOLDER_BOOKMARK_LIMIT,
        )?;
        assert_eq!(listing.files.len(), 3);
        assert_eq!(listing.file_limit, None);
        assert!(!listing.file_limit_reached);
        assert!(!listing.truncated);

        let result = bookmark_live_folder_recursive(
            &case_path,
            bookmark_id,
            evidence_id,
            "folder",
            &evidence_source.to_string_lossy(),
            0,
            "",
            "",
            listing,
        )?;
        assert_eq!(result.items_added, 3);
        assert_eq!(result.file_limit, None);
        assert!(!result.file_limit_reached);
        assert_eq!(result.skipped_count, 0);
        assert!(!result.truncated);

        let items = list_bookmark_items(&case_path, Some(bookmark_id))?;
        assert_eq!(items.len(), 3);
        let names: Vec<_> = items
            .iter()
            .filter_map(|item| item.display_name.clone())
            .collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"c.txt".to_string()));
        let nested = items
            .iter()
            .find(|item| item.display_name.as_deref() == Some("c.txt"))
            .expect("nested file bookmarked");
        assert_eq!(nested.item_ref_json["kind"], serde_json::json!("live_file"));
        assert_eq!(
            nested.item_ref_json["relative_path"],
            serde_json::json!("Sub/c.txt")
        );
        assert_eq!(nested.item_ref_json["size_bytes"], serde_json::json!(6));
        assert!(nested.item_ref_json["metadata"].is_object());

        // filesystem_entries must stay untouched by a live/recursive bookmark - this
        // is explicitly a no-indexing action, same guarantee as a single live bookmark.
        assert_eq!(filesystem_entry_count(&case_path)?, 0);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_source);
        Ok(())
    }

    #[test]
    fn bookmark_item_add_rejects_invalid_fields() -> Result<()> {
        let case_path = unique_case_path("bookmark-item-invalid");
        create_test_case(&case_path)?;
        let bookmark_id = create_test_bookmark(&case_path)?;

        let mut bad_json = test_bookmark_item_options(bookmark_id);
        bad_json.item_ref_json = serde_json::json!("not an object");
        let err = add_bookmark_item(&case_path, bad_json)
            .expect_err("non-object item_ref_json should be rejected")
            .to_string();
        assert!(err.contains("item_ref_json"));

        let mut bad_offset = test_bookmark_item_options(bookmark_id);
        bad_offset.selection_offset = Some(-1);
        let err = add_bookmark_item(&case_path, bad_offset)
            .expect_err("negative offset should be rejected")
            .to_string();
        assert!(err.contains("selection_offset"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn report_data_filters_report_enabled_bookmarks_and_items() -> Result<()> {
        let case_path = unique_case_path("report-data");
        create_test_case(&case_path)?;
        let report_folder_id =
            create_bookmark_folder(&case_path, None, "Report", Some("Visible"), true)?;
        let hidden_folder_id = create_bookmark_folder(&case_path, None, "Hidden", None, false)?;
        let included_bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: report_folder_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: Some("Document".to_string()),
                title: Some("Important finding".to_string()),
                examiner_comment: Some("Include this".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: report_folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: None,
                title: Some("Excluded finding".to_string()),
                examiner_comment: None,
                in_report: false,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id: hidden_folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: None,
                title: Some("Hidden folder finding".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: included_bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Selected bytes".to_string()),
                logical_path: Some("/case/file.txt".to_string()),
                selection_offset: Some(5),
                selection_length: Some(4),
                data_preview: Some("data".to_string()),
                item_ref_json: serde_json::json!({ "kind": "selection" }),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: included_bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: Some(90),
                display_name: Some("Second selected item".to_string()),
                logical_path: Some("/case/second.txt".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("more data".to_string()),
                item_ref_json: serde_json::json!({ "kind": "selection" }),
            },
        )?;

        let report = report_data(&case_path)?;
        assert_eq!(report.folders.len(), 1);
        assert_eq!(report.folders[0].name, "Report");
        assert_eq!(report.folders[0].bookmarks.len(), 1);
        assert_eq!(
            report.folders[0].bookmarks[0].title.as_deref(),
            Some("Important finding")
        );
        assert_eq!(report.folders[0].bookmarks[0].items.len(), 2);
        assert_eq!(
            report.folders[0].bookmarks[0].items[0]
                .display_name
                .as_deref(),
            Some("Selected bytes")
        );
        let html = render_report_html(&report);
        assert!(html.contains("<th>Position</th>"));
        assert!(!html.contains("<th>Order</th>"));
        assert!(html.contains("<tr><td>1</td><td>Selected bytes</td>"));
        assert!(html.contains("<tr><td>2</td><td>Second selected item</td>"));
        assert!(!html.contains("<tr><td>10</td><td>Selected bytes</td>"));
        assert!(!html.contains("<tr><td>90</td><td>Second selected item</td>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_escapes_content() -> Result<()> {
        let case_path = unique_case_path("report-html");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "<Findings>", None, true)?;
        create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: None,
                title: Some("<script>alert(1)</script>".to_string()),
                examiner_comment: Some("A&B".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("&lt;Findings&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("A&amp;B"));
        assert!(!html.contains("<script>alert(1)</script>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn raw_disk_search_reports_stop_reason_result_vs_byte_vs_eof() -> Result<()> {
        // EA-009 known-answer: the scan must report WHY it stopped so the
        // examiner gets correct coverage guidance - a result-cap stop must not
        // be reported as (or conflated with) a byte-limit stop.
        let case_path = unique_case_path("ea009-stop-reason");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("ea009-stop-reason-source");
        let evidence_path = evidence_dir.join("marks.bin");
        let mut data = vec![b'.'; 256];
        for off in [0usize, 100, 200] {
            data[off..off + 4].copy_from_slice(b"MARK");
        }
        fs::write(&evidence_path, &data)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path,
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        // Result cap reached before the (unlimited) byte budget -> ResultLimit.
        let capped = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: "MARK".to_string(),
                max_results: 2,
                max_scan_bytes: 0,
            },
        )?;
        assert_eq!(capped.stop_reason, RawSearchStopReason::ResultLimit);
        assert!(capped.truncated);

        // Byte budget reached before scanning to the end -> ByteLimit.
        let byte_limited = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: "MARK".to_string(),
                max_results: 1000,
                max_scan_bytes: 50,
            },
        )?;
        assert_eq!(byte_limited.stop_reason, RawSearchStopReason::ByteLimit);
        assert!(byte_limited.truncated);

        // Whole file scanned, all matches found within the cap -> Eof, complete.
        let complete = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                evidence_id,
                query: "MARK".to_string(),
                max_results: 1000,
                max_scan_bytes: 0,
            },
        )?;
        assert_eq!(complete.stop_reason, RawSearchStopReason::Eof);
        assert!(!complete.truncated);
        assert_eq!(
            complete
                .hits
                .iter()
                .filter(|hit| hit.encoding == "ascii")
                .count(),
            3
        );

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn search_page_apis_reject_oversized_responses_without_clamping() {
        let missing_case = Path::new("does-not-need-to-exist.kdft.sqlite");
        let deep_error = deep_search_page(
            missing_case,
            DeepSearchOptions {
                query: "needle".to_string(),
                evidence_id: None,
                include_content: true,
                max_results: SEARCH_RESPONSE_PAGE_MAX + 1,
                max_file_bytes: 4096,
                category: None,
                file_types: None,
            },
            None,
            SEARCH_RESPONSE_PAGE_MAX + 1,
        )
        .expect_err("oversized Deep Search page must be rejected");
        assert!(deep_error.to_string().contains("response maximum"));

        let raw_error = raw_disk_search_page(
            missing_case,
            RawDiskSearchOptions {
                evidence_id: 1,
                query: "needle".to_string(),
                max_results: SEARCH_RESPONSE_PAGE_MAX + 1,
                max_scan_bytes: 0,
            },
            None,
        )
        .expect_err("oversized raw-search page must be rejected");
        assert!(raw_error.to_string().contains("response maximum"));
    }

    #[test]
    fn raw_search_cursor_pages_match_complete_scan_including_same_offset_encodings() -> Result<()> {
        let case_path = unique_case_path("raw-search-pages");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("raw-search-pages-source");
        let evidence_path = evidence_dir.join("same-offset.bin");
        fs::write(&evidence_path, [b'A', 0, b'A', 0, b'A', 0])?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path,
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let options = RawDiskSearchOptions {
            evidence_id,
            query: "A".to_string(),
            max_results: 2,
            max_scan_bytes: 0,
        };
        let complete = raw_disk_search(
            &case_path,
            RawDiskSearchOptions {
                max_results: 100,
                ..options.clone()
            },
        )?;
        assert!(complete.complete);
        let expected = complete
            .hits
            .iter()
            .map(|hit| (hit.offset, hit.encoding.clone()))
            .collect::<Vec<_>>();
        assert!(expected.contains(&(0, "ascii".to_string())));
        assert!(expected.contains(&(0, "utf16le".to_string())));

        let mut cursor = None;
        let mut actual = Vec::new();
        loop {
            let page = raw_disk_search_page(&case_path, options.clone(), cursor)?;
            assert!(page.hits.len() <= 2);
            actual.extend(
                page.hits
                    .iter()
                    .map(|hit| (hit.offset, hit.encoding.clone())),
            );
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            assert_eq!(page.stop_reason, RawSearchStopReason::ResultLimit);
            cursor = Some(page.next_cursor.context("result page needs a cursor")?);
        }
        assert_eq!(actual, expected);

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn structured_container_extensions_are_recognized() {
        for ext in [
            "vmdk", "VMDK", "vhd", "vhdx", "avhdx", "e01", "Ex01", "qcow2", "aff4",
        ] {
            assert!(
                is_structured_container_extension(Path::new(&format!("disk.{ext}"))),
                "{ext} should be treated as a structured container extension"
            );
        }
        for ext in ["img", "dd", "raw", "bin", "001"] {
            assert!(
                !is_structured_container_extension(Path::new(&format!("disk.{ext}"))),
                "{ext} should NOT be treated as a structured container"
            );
        }
        assert!(!is_structured_container_extension(Path::new("noext")));
    }

    #[test]
    fn undecodable_vmdk_is_refused_with_no_completed_process() -> Result<()> {
        // EA-002 known-answer: a .vmdk that can only open as RAW was not truly
        // decoded. open_disk_image refuses it; attach stays lightweight; and
        // processing must fail with NO completed/truncated index job and NO
        // synthetic entries (so an examiner can never believe a VM disk was
        // examined when only its descriptor was read).
        let case_path = unique_case_path("ea002-undecodable-vmdk");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("ea002-vmdk-source");
        let vmdk_path = evidence_dir.join("split.vmdk");
        fs::write(&vmdk_path, vec![0_u8; 2048])?;

        assert!(
            open_disk_image(&vmdk_path).is_err(),
            "a .vmdk that only decodes as RAW must be refused"
        );

        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: vmdk_path,
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        assert!(
            process_evidence(
                &case_path,
                ProcessEvidenceOptions {
                    evidence_id,
                    max_entries: 0,
                },
            )
            .is_err(),
            "processing an undecodable container must fail"
        );

        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let completed_jobs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM evidence_jobs
             WHERE case_id = ?1 AND evidence_id = ?2 AND job_type = 'filesystem_index'
               AND status IN ('completed', 'truncated')",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(
            completed_jobs, 0,
            "an undecodable container must not record a completed/truncated index job"
        );
        let failed_jobs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM evidence_jobs
             WHERE case_id = ?1 AND evidence_id = ?2 AND job_type = 'filesystem_index'
               AND status = 'failed'",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(
            failed_jobs, 1,
            "the rolled-back attempt should remain visible as a failed job"
        );
        let entry_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
            params![case_id, evidence_id],
            |row| row.get(0),
        )?;
        assert_eq!(
            entry_count, 0,
            "an undecodable container must index no entries"
        );

        drop(conn);
        let report = report_data(&case_path)?;
        assert_eq!(
            report.evidence[0].latest_process_job_status.as_deref(),
            Some("failed")
        );
        assert_eq!(report.evidence[0].latest_process_entries_indexed, Some(0));
        assert!(report.evidence[0]
            .processing_coverage
            .contains("FAILED INDEXING"));
        assert!(render_report_html(&report).contains("FAILED INDEXING"));
        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn split_raw_reader_concatenates_segments_and_detects_gaps() -> Result<()> {
        let dir = unique_temp_dir("split-raw");
        fs::write(dir.join("disk.001"), b"abc")?;
        fs::write(dir.join("disk.002"), b"defg")?;
        fs::write(dir.join("disk.003"), b"hi")?;

        // Auto kind detection treats the first segment as an image.
        assert!(looks_like_image(&dir.join("disk.001")));
        assert!(!looks_like_image(&dir.join("report.2024")));

        let mut opened = open_disk_image(&dir.join("disk.001"))?;
        assert_eq!(opened.decoded_size, 9);
        assert!(opened.format.contains("SplitRaw(3 segments)"));
        let mut all = Vec::new();
        opened.reader.read_to_end(&mut all)?;
        assert_eq!(all, b"abcdefghi");

        // Reads and seeks spanning segment boundaries.
        opened.reader.seek(SeekFrom::Start(2))?;
        let mut buf = [0_u8; 4];
        opened.reader.read_exact(&mut buf)?;
        assert_eq!(&buf, b"cdef");
        opened.reader.seek(SeekFrom::End(-3))?;
        let mut tail = Vec::new();
        opened.reader.read_to_end(&mut tail)?;
        assert_eq!(tail, b"ghi");

        // Adding a non-first segment is rejected with guidance.
        let Err(err) = open_disk_image(&dir.join("disk.002")) else {
            panic!("expected non-first segment to be rejected");
        };
        assert!(err.to_string().contains("first segment"));

        // A single .001 with no siblings is ordinary raw evidence.
        let single_dir = unique_temp_dir("split-raw-single");
        fs::write(single_dir.join("lonely.001"), b"xyz")?;
        let single = open_disk_image(&single_dir.join("lonely.001"))?;
        assert_eq!(single.decoded_size, 3);
        assert!(!single.format.contains("SplitRaw"));

        // Attach-time size records the decoded (total) size, not segment 1.
        let case_path = unique_case_path("split-raw-size");
        create_test_case(&case_path)?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: dir.join("disk.001"),
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let evidence = list_evidence(&case_path)?;
        assert_eq!(evidence[0].id, evidence_id);
        assert_eq!(evidence[0].size_bytes, Some(9));

        // A gap in the sequence refuses to open instead of truncating.
        fs::remove_file(dir.join("disk.002"))?;
        let Err(err) = open_disk_image(&dir.join("disk.001")) else {
            panic!("expected segment gap to be rejected");
        };
        assert!(err.to_string().contains("segment gap"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&single_dir);
        Ok(())
    }

    #[test]
    fn report_includes_technical_details_directory_tree_and_integrity_hash() -> Result<()> {
        let case_path = unique_case_path("report-tech-details");
        create_test_case(&case_path)?;

        let evidence_dir = unique_temp_dir("report-tree-evidence");
        fs::create_dir_all(evidence_dir.join("docs").join("sub"))?;
        fs::write(evidence_dir.join("docs").join("note.txt"), b"hello")?;
        fs::write(
            evidence_dir.join("docs").join("sub").join("inner.txt"),
            b"x",
        )?;
        fs::write(evidence_dir.join("root.bin"), b"abc")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        process_evidence(
            &case_path,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let report = report_data_with_directory_structure(&case_path, 2000)?;
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].id, evidence_id);
        assert!(report.evidence[0].entries_indexed > 0);
        assert_eq!(report.evidence[0].sha256, None);
        assert_eq!(report.directory_trees.len(), 1);
        let tree = &report.directory_trees[0];
        assert!(!tree.truncated);
        assert!(tree.lines.iter().any(|line| line.name == "docs"));
        assert!(tree.lines.iter().any(|line| line.name == "sub"));
        // Directory structure is folders only: files must not appear.
        assert!(!tree.lines.iter().any(|line| line.name == "note.txt"));
        assert!(!tree.lines.iter().any(|line| line.name == "root.bin"));
        assert!(tree.lines.iter().all(|line| line.entry_kind == "directory"));

        // The lean report (used by /api/state) must stay tree-free.
        assert!(report_data(&case_path)?.directory_trees.is_empty());

        let rendered = render_report(&report);
        assert!(rendered.html.contains("Technical Details"));
        assert!(rendered.html.contains("Evidence Sources"));
        assert!(rendered.html.contains("Directory Structure - "));
        assert!(rendered.html.contains("kdft-band"));
        assert!(rendered.html.contains("KDFT report authenticity"));
        assert!(rendered.html.contains("not computed"));

        // Integrity: the prefix hash must cover exactly the bytes before the
        // footer and must be named for what it covers.
        let marker = "<footer class=\"kdft-integrity\"";
        let footer_start = rendered
            .html
            .find(marker)
            .expect("integrity footer present");
        let recomputed = sha256_hex(&rendered.html.as_bytes()[..footer_start]);
        assert_eq!(recomputed, rendered.content_prefix_sha256);
        assert!(rendered.html.contains(&rendered.content_prefix_sha256));
        assert!(rendered.html.contains("report_file_sha256"));

        // Truncation bound is honored.
        let bounded = report_data_with_directory_structure(&case_path, 1)?;
        assert!(bounded.directory_trees[0].truncated);
        assert_eq!(bounded.directory_trees[0].lines.len(), 1);

        // Write the report like the export handlers, hash the complete file
        // with standard SHA-256, and require the
        // audit event to carry BOTH digests under explicit names. A verifier
        // running plain `sha256sum` on the file must reproduce
        // report_file_sha256 exactly.
        let report_file =
            std::env::temp_dir().join(format!("kdft-ea008-report-{}.html", std::process::id()));
        fs::write(&report_file, &rendered.html)?;
        let report_file_sha256 = sha256_hex(&fs::read(&report_file)?);
        assert_ne!(
            report_file_sha256, rendered.content_prefix_sha256,
            "file hash must differ from the embedded prefix hash"
        );
        record_report_export(
            &case_path,
            &report_file.to_string_lossy(),
            &rendered.content_prefix_sha256,
            &report_file_sha256,
        )?;
        {
            let conn = open_existing_case(&case_path)?;
            let details: String = conn.query_row(
                "SELECT details_json FROM audit_events
                 WHERE event_type = 'report.export'
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )?;
            let details: serde_json::Value = serde_json::from_str(&details)?;
            assert_eq!(
                details["content_prefix_sha256"].as_str(),
                Some(rendered.content_prefix_sha256.as_str())
            );
            assert_eq!(
                details["report_file_sha256"].as_str(),
                Some(report_file_sha256.as_str())
            );
            assert!(
                details.get("sha256").is_none(),
                "ambiguous legacy sha256 field must be gone"
            );
        }
        let _ = fs::remove_file(&report_file);

        let _ = fs::remove_dir_all(&evidence_dir);
        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_search_result_forensic_context() -> Result<()> {
        let case_path = unique_case_path("report-search-context");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Search Results", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Search Result".to_string()),
                title: Some("Keyword hit".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("message.eml".to_string()),
                logical_path: Some("/Recovery/Deleted Files/message.eml".to_string()),
                selection_offset: Some(16),
                selection_length: Some(7),
                data_preview: Some("keyword".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "search_result",
                    "match_kind": "content",
                    "logical_path": "/Recovery/Deleted Files/message.eml",
                    "relative_path": "/Recovery/Deleted Files/message.eml",
                    "size_bytes": 42,
                    "is_deleted": true,
                    "storage_area": "deleted_filesystem_record",
                    "is_file_slack": false,
                    "is_unallocated": false,
                    "mft_record_logical_offset": 2048,
                    "mft_record_physical_offset": 1050624,
                    "file_data_logical_offset": 4096,
                    "file_data_physical_offset": 1052672,
                    "finding_logical_offset": 16,
                    "selection_length": 7,
                    "metadata": {
                        "ntfs_creation_time_utc": "2026-06-30T20:00:00Z",
                        "ntfs_modification_time_utc": "2026-06-30T20:01:00Z",
                        "ntfs_access_time_utc": "2026-06-30T20:02:00Z",
                        "ntfs_mft_record_modification_time_utc": "2026-06-30T20:03:00Z"
                    }
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("<span class=\"meta\">search_result</span>"));
        assert!(html.contains("<dt>Artifact</dt><dd>Forensic Finding</dd>"));
        assert!(html
            .contains("<dt>KDFT Internal Path</dt><dd>/Recovery/Deleted Files/message.eml</dd>"));
        assert!(html.contains("<dt>Deleted</dt><dd>true</dd>"));
        assert!(html.contains("<dt>Storage Area</dt><dd>deleted_filesystem_record</dd>"));
        assert!(html.contains("<dt>Finding Offset</dt><dd>16</dd>"));
        assert!(html.contains("<dt>MFT Record Physical Offset</dt><dd>1050624</dd>"));
        assert!(html.contains("<dt>File Data Physical Offset</dt><dd>1052672</dd>"));
        assert!(html.contains("<dt>Created</dt><dd>2026-06-30T20:00:00Z</dd>"));
        assert!(html.contains("<dt>MFT Modified</dt><dd>2026-06-30T20:03:00Z</dd>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_resolves_each_ntfs_time_role_once_from_entry_api() -> Result<()> {
        const CREATED: &str = "2009-12-11T09:01:02Z";
        const MODIFIED: &str = "2009-12-11T10:03:04Z";
        const ACCESSED: &str = "2009-12-11T11:05:06Z";
        const MFT_MODIFIED: &str = "2009-12-11T12:07:08Z";

        let case_path = unique_case_path("report-single-source-ntfs-times");
        create_test_case(&case_path)?;
        let source_dir = unique_temp_dir("report-single-source-ntfs-times-source");
        fs::write(source_dir.join("Nitroba work.odt"), b"timestamp oracle")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: source_dir.clone(),
                kind: EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let metadata = serde_json::json!({
            "artifact_kind": "filesystem_entry",
            "filesystem_parser": "ntfs",
            "ntfs_path": "Nitroba work.odt",
            "created_utc": null,
            "modified_utc": null,
            "accessed_utc": null,
            "ntfs_standard_creation_time_utc": CREATED,
            "ntfs_standard_modification_time_utc": MODIFIED,
            "ntfs_standard_access_time_utc": ACCESSED,
            "ntfs_standard_mft_record_modification_time_utc": MFT_MODIFIED,
            "ntfs_creation_time_utc": "2001-01-01T00:00:00Z",
            "ntfs_modification_time_utc": "2001-01-02T00:00:00Z",
            "ntfs_access_time_utc": "2001-01-03T00:00:00Z",
            "ntfs_mft_record_modification_time_utc": "2001-01-04T00:00:00Z"
        });
        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, size_bytes, metadata_json
             ) VALUES (?1, ?2, '/internal/nitroba.odt', 'Nitroba work.odt', 'file', 16, ?3)",
            params![case_id, evidence_id, metadata.to_string()],
        )?;
        let entry_id = conn.last_insert_rowid();
        drop(conn);

        let api_entry = filesystem_entry_by_id(&case_path, entry_id)?
            .expect("known NTFS timestamp entry should be returned by the entry API");
        assert_eq!(
            api_entry.metadata_json["ntfs_standard_creation_time_utc"].as_str(),
            Some(CREATED)
        );
        assert_eq!(
            api_entry.metadata_json["ntfs_standard_modification_time_utc"].as_str(),
            Some(MODIFIED)
        );
        assert_eq!(
            api_entry.metadata_json["ntfs_standard_access_time_utc"].as_str(),
            Some(ACCESSED)
        );
        assert_eq!(
            api_entry.metadata_json["ntfs_standard_mft_record_modification_time_utc"].as_str(),
            Some(MFT_MODIFIED)
        );

        let bookmark_id = create_test_bookmark(&case_path)?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: Some(entry_id),
                item_order: None,
                display_name: None,
                logical_path: None,
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json: serde_json::json!({}),
            },
        )?;
        let html = render_report_html(&report_data(&case_path)?);
        assert_eq!(html.matches("<dt>Created</dt>").count(), 1);
        assert_eq!(html.matches("<dt>Modified</dt>").count(), 1);
        assert_eq!(html.matches("<dt>Accessed</dt>").count(), 1);
        assert_eq!(html.matches("<dt>MFT Modified</dt>").count(), 1);
        assert!(html.contains(&format!("<dt>Created</dt><dd>{CREATED}</dd>")));
        assert!(html.contains(&format!("<dt>Modified</dt><dd>{MODIFIED}</dd>")));
        assert!(html.contains(&format!("<dt>Accessed</dt><dd>{ACCESSED}</dd>")));
        assert!(html.contains(&format!("<dt>MFT Modified</dt><dd>{MFT_MODIFIED}</dd>")));
        assert!(!html.contains("<dt>Created</dt><dd>2001-01-01T00:00:00Z</dd>"));
        assert!(!html.contains("verified absent"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_raw_whole_disk_bitwise_hit() -> Result<()> {
        let case_path = unique_case_path("report-raw-bitwise-hit");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("report-raw-bitwise-hit-source");
        let evidence_path = evidence_dir.join("disk.img");
        fs::write(&evidence_path, vec![0_u8; 4096])?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path,
                kind: EvidenceKind::File,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let hash = hash_evidence(&case_path, evidence_id)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Raw Hits", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Whole-Disk Bitwise Hit".to_string()),
                title: Some("MBR signature".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("Bitwise hit at offset 510".to_string()),
                logical_path: Some("raw image whole-disk scan".to_string()),
                selection_offset: Some(510),
                selection_length: Some(2),
                data_preview: Some("55 AA".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "highlighted_bytes",
                    "source": "raw_image_whole_disk_scan",
                    "evidence_id": evidence_id,
                    "entry_id": null,
                    "logical_path": "raw image whole-disk scan",
                    "display_name": "Bitwise hit at offset 510",
                    "selection_logical_offset_start": 510,
                    "selection_logical_offset_end": 511,
                    "selection_physical_offset_start": 510,
                    "selection_physical_offset_end": 511,
                    "selection_length_bytes": 2,
                    "physical_offset_basis": "raw evidence byte offset, whole-image scan from offset 0 - exact, not fragment-approximate",
                    "sector": 0,
                    "sector_size": 512,
                    "partition_index": 0,
                    "volume_name": "001-system",
                    "partition_start_offset": 512,
                    "filesystem": "FAT",
                    "region": "in-partition",
                    "encoding": "hex",
                    "hex_preview": "55 AA",
                    "ascii_preview": "U.",
                    "query": "hex:55 AA",
                    "encodings": ["hex"],
                    "searched_at": "2026-07-12T00:00:00Z",
                    "actor": "Test Examiner",
                    "scan_start": 0,
                    "max_scan_bytes": 33554432,
                    "bytes_scanned": 4096,
                    "total_size": 8192
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("<span class=\"meta\">highlighted_bytes</span>"));
        assert!(html.contains("<dt>Artifact</dt><dd>Whole-Disk Bitwise Hit</dd>"));
        assert!(html.contains("<dt>Evidence Source</dt><dd>disk.img</dd>"));
        // EA-001/EA-004: a file-evidence digest is not "Acquisition SHA-256",
        // and a hash not captured in the finding's item_ref is shown as the
        // current evidence value - never backfilled into the scan-time slot.
        assert!(!html.contains("<dt>Acquisition SHA-256</dt>"));
        assert!(html.contains(
            "<dt>SHA-256 (evidence file)</dt><dd>evidence not hashed at search time - compute the hash before relying on these results in court</dd>"
        ));
        assert!(html.contains(&format!(
            "<dt>SHA-256 (evidence file) (current evidence value, not captured with this finding)</dt><dd>{}</dd>",
            hash.sha256_hex
        )));
        assert!(html.contains("<dt>Byte Offset</dt><dd>510 (0x1FE)</dd>"));
        assert!(html.contains("<dt>Sector</dt><dd>0</dd>"));
        assert!(html.contains("<dt>Sector Size</dt><dd>512</dd>"));
        assert!(html.contains("<dt>Volume</dt><dd>001-system</dd>"));
        assert!(html.contains("<dt>Volume Start Offset</dt><dd>512</dd>"));
        assert!(html.contains("<dt>Region</dt><dd>in-partition</dd>"));
        assert!(html.contains("<dt>Encoding</dt><dd>hex</dd>"));
        assert!(html.contains("<dt>Selection Length</dt><dd>2</dd>"));
        assert!(html.contains("<dt>Hex Preview</dt><dd>55 AA</dd>"));
        assert!(html.contains("<dt>ASCII Preview</dt><dd>U.</dd>"));
        assert!(html.contains("<dt>Search Query</dt><dd>hex:55 AA</dd>"));
        assert!(html.contains("<dt>Search Examiner</dt><dd>Test Examiner</dd>"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn render_report_html_labels_image_digest_as_decoded_media_not_acquisition() -> Result<()> {
        // EA-001 known-answer: for image evidence the captured digest is the
        // DECODED logical-media hash. A verifier hashing the container file
        // cannot reproduce it, so the report must label it "Logical media
        // SHA-256 (decoded image stream)" and never "Acquisition SHA-256".
        // The finding captured its own scan-time hash, so it renders from the
        // item_ref (not backfilled from the evidence row).
        let case_path = unique_case_path("report-image-media-hash-label");
        create_test_case(&case_path)?;
        let evidence_dir = unique_temp_dir("report-image-media-hash-source");
        let evidence_path = evidence_dir.join("image.raw");
        fs::write(&evidence_path, vec![0_u8; 4096])?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: evidence_path,
                kind: EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let scan_time_hash = "a".repeat(64);
        let folder_id = create_bookmark_folder(&case_path, None, "Raw Hits", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::HighlightedData,
                data_type: Some("Whole-Disk Bitwise Hit".to_string()),
                title: Some("hit".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("hit".to_string()),
                logical_path: Some("raw image whole-disk scan".to_string()),
                selection_offset: Some(0),
                selection_length: Some(2),
                data_preview: Some("00 00".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "highlighted_bytes",
                    "source": "raw_image_whole_disk_scan",
                    "evidence_id": evidence_id,
                    "entry_id": null,
                    "logical_path": "raw image whole-disk scan",
                    "display_name": "hit",
                    "evidence_sha256_hex": scan_time_hash,
                    "selection_logical_offset_start": 0,
                    "selection_logical_offset_end": 1,
                    "selection_length_bytes": 2,
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(!html.contains("<dt>Acquisition SHA-256</dt>"));
        assert!(html.contains(&format!(
            "<dt>Logical media SHA-256 (decoded image stream)</dt><dd>{scan_time_hash}</dd>"
        )));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_live_bookmark_metadata() -> Result<()> {
        let case_path = unique_case_path("report-live-bookmark-context");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Live Browse", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::NotableFile,
                data_type: Some("Live file".to_string()),
                title: Some("Sample Findings Report.docx".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Sample Findings Report.docx".to_string()),
                logical_path: Some(
                    "[vol 1] /Users/examiner/Downloads/Sample Findings Report.docx".to_string(),
                ),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("Live file | 42 B | modified 2026-07-07T05:00:00Z".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "live_file",
                    "entry_kind": "file",
                    "evidence_id": 1,
                    "logical_path": "[vol 1] /Users/examiner/Downloads/Sample Findings Report.docx",
                    "relative_path": "/Users/examiner/Downloads/Sample Findings Report.docx",
                    "display_name": "Sample Findings Report.docx",
                    "volume": 1,
                    "path": "/Users/examiner/Downloads/Sample Findings Report.docx",
                    "filesystem": "NTFS",
                    "volume_start_offset": 1048576,
                    "volume_size_bytes": 4096,
                    "size_bytes": 42,
                    "ntfs_file_record_number": 123,
                    "mft_record_logical_offset": 6291456,
                    "mft_record_physical_offset": 7340032,
                    "file_data_logical_offset": 8192,
                    "file_data_physical_offset": 1056768,
                    "created_utc": "2026-07-07T04:00:00Z",
                    "modified_utc": "2026-07-07T05:00:00Z",
                    "accessed_utc": "2026-07-07T06:00:00Z",
                    "ntfs_mft_record_modification_time_utc": "2026-07-07T06:30:00Z",
                    "is_deleted": false,
                    "file_extension": "docx",
                    "metadata": {
                        "source_kind": "image",
                        "source_path": "E:\\\\w10_malw.vdi",
                        "volume_filesystem": "NTFS"
                    }
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("<dt>Artifact</dt><dd>Live Browse File</dd>"));
        assert!(html.contains("<dt>Source Path (exact)</dt><dd>/Users/examiner/Downloads/Sample Findings Report.docx</dd>"));
        assert!(html.contains("<dt>KDFT Internal Path</dt><dd>[vol 1] /Users/examiner/Downloads/Sample Findings Report.docx</dd>"));
        assert!(html.contains("<dt>Size</dt><dd>42</dd>"));
        assert!(html.contains("<dt>Deleted</dt><dd>false</dd>"));
        assert!(html.contains("<dt>NTFS File Record</dt><dd>123</dd>"));
        assert!(html.contains("<dt>MFT Record Logical Offset</dt><dd>6291456</dd>"));
        assert!(html.contains("<dt>MFT Record Physical Offset</dt><dd>7340032</dd>"));
        assert!(html.contains("<dt>File Data Logical Offset</dt><dd>8192</dd>"));
        assert!(html.contains("<dt>File Data Physical Offset</dt><dd>1056768</dd>"));
        assert!(html.contains("<dt>Created</dt><dd>2026-07-07T04:00:00Z</dd>"));
        assert!(html.contains("<dt>Modified</dt><dd>2026-07-07T05:00:00Z</dd>"));
        assert!(html.contains("<dt>Accessed</dt><dd>2026-07-07T06:00:00Z</dd>"));
        assert!(html.contains("<dt>MFT Modified</dt><dd>2026-07-07T06:30:00Z</dd>"));
        assert!(html.contains("&quot;metadata&quot;"));
        assert!(html.contains("E:\\\\w10_malw.vdi"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_formats_browser_activity_items() -> Result<()> {
        let case_path = unique_case_path("report-browser-activity");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Browser Activities", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Browser Activity".to_string()),
                title: Some("Visit: Example & Evidence".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Example & Evidence".to_string()),
                logical_path: Some("/Browser Activities/Visits/example.com/1.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some(
                    "2026-06-28T10:00:00Z | Example & Evidence | https://example.com/<q>"
                        .to_string(),
                ),
                item_ref_json: serde_json::json!({
                    "kind": "browser_activity",
                    "activity_kind": "browser_history_visit",
                    "url": "https://example.com/<q>",
                    "title": "Example & Evidence",
                    "visit_time_utc": "2026-06-28T10:00:00Z",
                    "source_file_modified_utc": "2026-06-28T10:05:00Z",
                    "source_file_time_basis": "original_evidence_filesystem",
                    "metadata": {
                        "transition_type": "typed",
                        "visit_count": 3
                    }
                }),
            },
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "URL: Example",
            "/Browser Activities/URLs/example.com/1.record",
            serde_json::json!({
                "activity_kind": "browser_url",
                "url": "https://example.com/url",
                "title": "Example URL",
                "last_visit_time_utc": "2026-06-28T09:00:00Z",
                "visit_count": 4,
                "source_artifact": "History"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Search: keyword",
            "/Browser Activities/Searches/keyword-1.record",
            serde_json::json!({
                "activity_kind": "browser_search_term",
                "search_term": "keyword",
                "url": "https://search.example/?q=keyword",
                "last_used_utc": "2026-06-28T09:30:00Z",
                "times_used": 2
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Omnibox: typed query",
            "/Browser Activities/Omnibox/shortcut-typed_query.record",
            serde_json::json!({
                "activity_kind": "browser_omnibox_shortcut",
                "text": "typed query",
                "url": "https://search.example/?q=typed+query",
                "last_access_time_utc": "2026-06-28T09:45:00Z",
                "number_of_hits": 5,
                "source_artifact": "Shortcuts"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Autofill: email",
            "/Browser Activities/Autofill/1-email.record",
            serde_json::json!({
                "activity_kind": "browser_autofill",
                "name": "email",
                "value": "examiner@example.test",
                "count": 3,
                "date_created_utc": "2026-06-28T09:50:00Z",
                "source_artifact": "Web Data"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Download: tool.zip",
            "/Browser Activities/Downloads/7-tool.zip.record",
            serde_json::json!({
                "activity_kind": "browser_download",
                "file_name": "tool.zip",
                "target_path": "C:\\Users\\me\\Downloads\\tool.zip",
                "site_url": "https://site.example/download",
                "tab_url": "https://example.com/download",
                "start_time_utc": "2026-06-28T11:00:00Z",
                "received_bytes": 2048,
                "download_url": "https://cdn.example/tool.zip",
                "state_label": "complete",
                "duration_human": "1.8s",
                "outcome_summary": "complete - 2,048 bytes in 1.8s"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Bookmark: Example",
            "/Browser Activities/Bookmarks/Bar/example.record",
            serde_json::json!({
                "activity_kind": "browser_bookmark",
                "name": "Example Bookmark",
                "url": "https://example.com/bookmark",
                "folder": "Bookmarks Bar",
                "date_added_utc": "2026-06-28T08:00:00Z"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Login: example.com",
            "/Browser Activities/Logins/example.com/user-1.record",
            serde_json::json!({
                "activity_kind": "browser_login",
                "host": "example.com",
                "username": "user@example.com",
                "date_last_used_utc": "2026-06-28T12:00:00Z",
                "password_note": "encrypted password value not extracted"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Cookie: sid",
            "/Browser Activities/Cookies/example.com/sid-1.record",
            serde_json::json!({
                "activity_kind": "browser_cookie",
                "host": ".example.com",
                "cookie_name": "sid",
                "cookie_path": "/",
                "last_access_utc": "2026-06-28T12:30:00Z",
                "value_note": "encrypted cookie value not extracted"
            }),
        )?;
        add_browser_report_item(
            &case_path,
            bookmark_id,
            "Preference: Downloads",
            "/Browser Activities/Preferences/Downloads.record",
            serde_json::json!({
                "activity_kind": "browser_preference",
                "category": "downloads",
                "download_default_directory": "C:\\Users\\Examiner\\Downloads"
            }),
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("Browser Activity"));
        assert!(html.contains("<dd>Visit</dd>"));
        assert!(html.contains("Example &amp; Evidence"));
        assert!(html.contains("https://example.com/&lt;q&gt;"));
        assert!(html.contains("<dt>Transition</dt><dd>typed</dd>"));
        assert!(html.contains("<dt>Visit Count</dt><dd>3</dd>"));
        assert!(html.contains("<dt>Original Source File Modified</dt>"));
        assert!(html.contains("<dd>URL</dd>"));
        assert!(html.contains("<dt>Last Visit</dt><dd>2026-06-28T09:00:00Z</dd>"));
        assert!(html.contains("<dd>Search</dd>"));
        assert!(html.contains("<dt>Search Term</dt><dd>keyword</dd>"));
        assert!(html.contains("<dd>Omnibox Shortcut</dd>"));
        assert!(html.contains("<dt>Typed Text</dt><dd>typed query</dd>"));
        assert!(html.contains("<dd>Autofill</dd>"));
        assert!(html.contains("<dt>Typed Value</dt><dd>examiner@example.test</dd>"));
        assert!(html.contains("<dd>Download</dd>"));
        assert!(html.contains("<dt>File Name</dt><dd>tool.zip</dd>"));
        assert!(html.contains("<dt>Outcome</dt><dd>complete - 2,048 bytes in 1.8s</dd>"));
        assert!(html.contains("<dt>Site URL</dt><dd>https://site.example/download</dd>"));
        assert!(html.contains("<dt>Tab URL</dt><dd>https://example.com/download</dd>"));
        assert!(html.contains("<dd>Bookmark</dd>"));
        assert!(html.contains("<dt>Folder</dt><dd>Bookmarks Bar</dd>"));
        assert!(html.contains("<dd>Saved Login</dd>"));
        assert!(html.contains("<dt>Username</dt><dd>user@example.com</dd>"));
        assert!(html.contains("<dd>Cookie</dd>"));
        assert!(html.contains("<dt>Cookie Name</dt><dd>sid</dd>"));
        assert!(html.contains("<dd>Preference</dd>"));
        assert!(html.contains("<dt>Download Directory</dt><dd>C:\\Users\\Examiner\\Downloads</dd>"));
        assert!(!html.contains("https://example.com/<q>"));

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn render_report_html_keeps_browser_events_separate_from_source_macb() -> Result<()> {
        let case_path = unique_case_path("report-browser-display-times");
        create_test_case(&case_path)?;
        let folder_id = create_bookmark_folder(&case_path, None, "Search Hits", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Search Hit".to_string()),
                title: Some("Search hit: Example URL".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some("Example URL".to_string()),
                logical_path: Some("/Browser Activities/URLs/example.com/1.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("https://example.com/".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "search_result",
                    "match_kind": "metadata",
                    "logical_path": "/Browser Activities/URLs/example.com/1.record",
                    "display_name": "Example URL",
                    "metadata": {
                        "artifact_kind": "browser_url",
                        "url": "https://example.com/",
                        "last_visit_time_utc": "2026-06-28T09:00:00Z",
                        "source_file_time_basis": "original_evidence_filesystem",
                        "source_file_created_utc": "2026-06-28T10:01:00Z",
                        "source_file_modified_utc": "2026-06-28T10:05:00Z",
                        "source_file_accessed_utc": "2026-06-28T10:06:00Z"
                    }
                }),
            },
        )?;

        let html = render_report_html(&report_data(&case_path)?);
        assert!(html.contains("<dt>Last Visit</dt><dd>2026-06-28T09:00:00Z</dd>"));
        assert!(!html.contains("<dt>Created</dt><dd>2026-06-28T09:00:00Z</dd>"));
        assert!(!html.contains("<dt>Modified</dt><dd>2026-06-28T09:00:00Z</dd>"));
        assert!(!html.contains("<dt>Accessed</dt><dd>2026-06-28T09:00:00Z</dd>"));
        assert!(html.contains("<dt>Original Source File Created</dt><dd>2026-06-28T10:01:00Z</dd>"));
        assert!(
            html.contains("<dt>Original Source File Modified</dt><dd>2026-06-28T10:05:00Z</dd>")
        );
        assert!(
            html.contains("<dt>Original Source File Accessed</dt><dd>2026-06-28T10:06:00Z</dd>")
        );

        cleanup_case_path(&case_path);
        Ok(())
    }

    #[test]
    fn report_category_bookmark_expands_contained_entries() -> Result<()> {
        let case_path = unique_case_path("report-category-expansion");
        create_test_case(&case_path)?;
        let source_dir = unique_temp_dir("report-category-expansion-source");
        fs::write(source_dir.join("History"), b"fixture")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: source_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        let insert_entry =
            |logical_path: &str, name: &str, metadata: serde_json::Value| -> Result<i64> {
                conn.execute(
                    "INSERT INTO filesystem_entries(
                         case_id, evidence_id, logical_path, name, entry_kind, metadata_json
                     ) VALUES (?1, ?2, ?3, ?4, 'record', ?5)",
                    params![
                        case_id,
                        evidence_id,
                        logical_path,
                        name,
                        metadata.to_string()
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            };
        let search_id = insert_entry(
            "/Browser Activities/Searches/cyberghost.record",
            "Search: cyberghost",
            serde_json::json!({
                "artifact_kind": "browser_search_term",
                "category_main": "Web Activity",
                "category_sub": "Searches",
                "search_term": "cyberghost",
                "url": "https://www.google.com/search?q=cyberghost",
                "last_used_utc": "2026-07-07T04:00:00Z",
                "source_artifact": "History"
            }),
        )?;
        let visit_id = insert_entry(
            "/Browser Activities/Visits/example.com/1.record",
            "Example visit",
            serde_json::json!({
                "artifact_kind": "browser_history_visit",
                "category_main": "Web Activity",
                "category_sub": "Visits",
                "title": "Example visit",
                "url": "https://example.com/",
                "visit_time_utc": "2026-07-07T04:05:00Z",
                "source_artifact": "History"
            }),
        )?;
        drop(conn);

        let folder_id = create_bookmark_folder(&case_path, None, "Categories", None, true)?;
        let searches_bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Category".to_string()),
                title: Some("Category: Web Activity / Searches".to_string()),
                examiner_comment: Some("Expand the selected browser search category.".to_string()),
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: searches_bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("Web Activity / Searches".to_string()),
                logical_path: Some("/Categories/Web Activity _ Searches.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("Web Activity / Searches".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "category",
                    "evidence_id": evidence_id,
                    "category_key": "Web Activity|||Searches",
                    "category_label": "Web Activity / Searches"
                }),
            },
        )?;

        let all_bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Category".to_string()),
                title: Some("Category: All Categories".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id: all_bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("All Categories".to_string()),
                logical_path: Some("/Categories/All Categories.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("All Categories".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "category",
                    "evidence_id": evidence_id,
                    "category_key": "",
                    "category_label": "All Categories"
                }),
            },
        )?;

        let report = report_data(&case_path)?;
        let bookmarks = &report.folders[0].bookmarks;
        let searches = bookmarks
            .iter()
            .find(|bookmark| bookmark.id == searches_bookmark_id)
            .expect("searches category bookmark");
        assert_eq!(searches.items.len(), 2);
        assert!(searches
            .items
            .iter()
            .any(|item| item.entry_id == Some(search_id)));
        assert!(!searches
            .items
            .iter()
            .any(|item| item.entry_id == Some(visit_id)));
        assert!(searches.items[0]
            .data_preview
            .as_deref()
            .unwrap_or("")
            .contains("Expanded to 1 non-directory entry"));

        let all = bookmarks
            .iter()
            .find(|bookmark| bookmark.id == all_bookmark_id)
            .expect("all categories bookmark");
        assert_eq!(all.items.len(), 3);
        assert!(all
            .items
            .iter()
            .any(|item| item.entry_id == Some(search_id)));
        assert!(all.items.iter().any(|item| item.entry_id == Some(visit_id)));

        let html = render_report_html(&report);
        assert!(html.contains("Expanded to 1 non-directory entry"));
        assert!(html.contains("<dt>Search Term</dt><dd>cyberghost</dd>"));
        assert!(html.contains("https://www.google.com/search?q=cyberghost"));
        assert!(html.contains("<dt>Visit Time</dt><dd>2026-07-07T04:05:00Z</dd>"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn report_category_bookmark_caps_large_category_expansion() -> Result<()> {
        let case_path = unique_case_path("report-category-expansion-limit");
        create_test_case(&case_path)?;
        let source_dir = unique_temp_dir("report-category-expansion-limit-source");
        fs::write(source_dir.join("History"), b"fixture")?;
        let evidence_id = add_evidence(
            &case_path,
            AddEvidenceOptions {
                path: source_dir.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let conn = open_existing_case(&case_path)?;
        let case_id = active_case_id(&conn)?;
        for index in 0..(REPORT_CATEGORY_EXPANSION_LIMIT + 2) {
            let suffix = format!("{index:04}");
            conn.execute(
                "INSERT INTO filesystem_entries(
                     case_id, evidence_id, logical_path, name, entry_kind, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, 'record', ?5)",
                params![
                    case_id,
                    evidence_id,
                    format!("/Browser Activities/Visits/example.com/{suffix}.record"),
                    format!("Visit {suffix}"),
                    serde_json::json!({
                        "artifact_kind": "browser_history_visit",
                        "category_main": "Web Activity",
                        "category_sub": "Visits",
                        "title": format!("Visit {suffix}"),
                        "url": format!("https://example.com/{suffix}")
                    })
                    .to_string()
                ],
            )?;
        }
        drop(conn);

        let folder_id = create_bookmark_folder(&case_path, None, "Categories", None, true)?;
        let bookmark_id = create_bookmark(
            &case_path,
            CreateBookmarkOptions {
                folder_id,
                bookmark_type: BookmarkType::Record,
                data_type: Some("Category".to_string()),
                title: Some("Category: All Categories".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )?;
        add_bookmark_item(
            &case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: Some(evidence_id),
                entry_id: None,
                item_order: None,
                display_name: Some("All Categories".to_string()),
                logical_path: Some("/Categories/All Categories.record".to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: Some("All Categories".to_string()),
                item_ref_json: serde_json::json!({
                    "kind": "category",
                    "evidence_id": evidence_id,
                    "category_key": "",
                    "category_label": "All Categories"
                }),
            },
        )?;

        let report = report_data(&case_path)?;
        let bookmark = &report.folders[0].bookmarks[0];
        assert_eq!(bookmark.items.len(), REPORT_CATEGORY_EXPANSION_LIMIT + 1);
        assert_eq!(
            bookmark
                .items
                .iter()
                .filter(|item| item.entry_id.is_some())
                .count(),
            REPORT_CATEGORY_EXPANSION_LIMIT
        );
        let summary = bookmark.items[0].data_preview.as_deref().unwrap_or("");
        assert!(summary.contains(&format!(
            "Expanded to first {} of {} non-directory entries",
            REPORT_CATEGORY_EXPANSION_LIMIT,
            REPORT_CATEGORY_EXPANSION_LIMIT + 2
        )));
        assert!(summary.contains("2 omitted"));

        cleanup_case_path(&case_path);
        let _ = fs::remove_dir_all(source_dir);
        Ok(())
    }

    fn add_browser_report_item(
        case_path: &Path,
        bookmark_id: i64,
        display_name: &str,
        logical_path: &str,
        mut item_ref_json: serde_json::Value,
    ) -> Result<()> {
        item_ref_json["kind"] = serde_json::json!("browser_activity");
        add_bookmark_item(
            case_path,
            CreateBookmarkItemOptions {
                bookmark_id,
                evidence_id: None,
                entry_id: None,
                item_order: None,
                display_name: Some(display_name.to_string()),
                logical_path: Some(logical_path.to_string()),
                selection_offset: None,
                selection_length: None,
                data_preview: None,
                item_ref_json,
            },
        )?;
        Ok(())
    }

    fn create_test_case(case_path: &Path) -> Result<i64> {
        create_case(
            case_path,
            CreateCaseOptions {
                name: "Unit Test Case".to_string(),
                examiner_name: Some("Test Examiner".to_string()),
                case_number: Some("UT-0001".to_string()),
                case_type: Some("Other".to_string()),
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
    }

    fn evidence_job_count(case_path: &Path) -> Result<i64> {
        let conn = open_existing_case(case_path)?;
        conn.query_row("SELECT COUNT(*) FROM evidence_jobs", [], |row| row.get(0))
            .context("counting evidence jobs")
    }

    fn audit_event_count(case_path: &Path) -> Result<i64> {
        let conn = open_existing_case(case_path)?;
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .context("counting audit events")
    }

    fn audit_event_actors(case_path: &Path) -> Result<Vec<String>> {
        let conn = open_existing_case(case_path)?;
        let mut stmt = conn.prepare("SELECT actor FROM audit_events ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .context("reading audit event actors")
    }

    fn create_test_bookmark(case_path: &Path) -> Result<i64> {
        let folder_id = create_bookmark_folder(case_path, None, "Findings", None, true)?;
        create_bookmark(case_path, test_bookmark_options(folder_id))
    }

    fn test_bookmark_options(folder_id: i64) -> CreateBookmarkOptions {
        CreateBookmarkOptions {
            folder_id,
            bookmark_type: BookmarkType::NotableFile,
            data_type: None,
            title: Some("Test bookmark".to_string()),
            examiner_comment: None,
            in_report: true,
            source_ref_json: serde_json::json!({}),
            content_ref_json: serde_json::json!({}),
        }
    }

    fn test_bookmark_item_options(bookmark_id: i64) -> CreateBookmarkItemOptions {
        CreateBookmarkItemOptions {
            bookmark_id,
            evidence_id: None,
            entry_id: None,
            item_order: None,
            display_name: None,
            logical_path: None,
            selection_offset: None,
            selection_length: None,
            data_preview: None,
            item_ref_json: serde_json::json!({}),
        }
    }

    fn artifact_count(entries: &[FilesystemEntry], artifact_kind: &str) -> usize {
        entries
            .iter()
            .filter(|entry| entry.metadata_json["artifact_kind"].as_str() == Some(artifact_kind))
            .count()
    }

    fn entry_with_artifact<'a>(
        entries: &'a [FilesystemEntry],
        artifact_kind: &str,
    ) -> &'a FilesystemEntry {
        entries
            .iter()
            .find(|entry| entry.metadata_json["artifact_kind"].as_str() == Some(artifact_kind))
            .expect("expected artifact entry")
    }

    fn create_empty_chromium_history_core(history_path: &Path) -> Result<()> {
        if let Some(parent) = history_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Connection::open(history_path)?.execute_batch(
            "CREATE TABLE urls(
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL,
                typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE visits(
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                transition INTEGER DEFAULT 0 NOT NULL
             );",
        )?;
        Ok(())
    }

    fn create_test_chromium_shortcuts(shortcuts_path: &Path) -> Result<()> {
        let conn = Connection::open(shortcuts_path)?;
        conn.execute_batch(
            "CREATE TABLE omni_box_shortcuts(
                id TEXT PRIMARY KEY,
                text TEXT,
                fill_into_edit TEXT,
                url TEXT,
                contents TEXT,
                description TEXT,
                type INTEGER,
                keyword TEXT,
                last_access_time INTEGER,
                number_of_hits INTEGER
             );
             INSERT INTO omni_box_shortcuts(
                id, text, fill_into_edit, url, contents, description, type,
                keyword, last_access_time, number_of_hits
             ) VALUES (
                'shortcut-guid-1', 'example forensic search', 'example forensic search',
                'https://search.example.test/?q=example+forensic+search',
                'example forensic search', 'Example Search', 0, 'example.test',
                13300000025000000, 7
             );",
        )?;
        Ok(())
    }

    fn create_test_chromium_web_data(web_data_path: &Path) -> Result<()> {
        let conn = Connection::open(web_data_path)?;
        conn.execute_batch(
            "CREATE TABLE autofill(
                name TEXT,
                value TEXT,
                count INTEGER,
                date_created INTEGER,
                date_last_used INTEGER
             );
             INSERT INTO autofill(name, value, count, date_created, date_last_used)
             VALUES ('email', 'examiner@example.test', 3, 1700000000, 1700003600),
                    ('case-note', 'typed evidence note', 2, 1700100000, 1700107200);",
        )?;
        Ok(())
    }

    fn create_test_chromium_history(history_path: &Path) -> Result<()> {
        let conn = Connection::open(history_path)?;
        conn.execute_batch(
            "CREATE TABLE urls(
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL,
                typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE visits(
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER DEFAULT 0 NOT NULL,
                segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE keyword_search_terms(
                keyword_id INTEGER NOT NULL,
                url_id INTEGER NOT NULL,
                term LONGVARCHAR NOT NULL,
                normalized_term LONGVARCHAR NOT NULL
             );
             CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                current_path LONGVARCHAR,
                target_path LONGVARCHAR,
                start_time INTEGER,
                end_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                danger_type INTEGER,
                interrupt_reason INTEGER,
                referrer LONGVARCHAR,
                tab_url LONGVARCHAR,
                mime_type LONGVARCHAR
             );",
        )?;
        conn.execute(
            "INSERT INTO keyword_search_terms(keyword_id, url_id, term, normalized_term)
             VALUES (1, 1, 'keyword', 'keyword')",
            [],
        )?;
        conn.execute(
            "INSERT INTO downloads(id, current_path, target_path, start_time, end_time,
                received_bytes, total_bytes, state, danger_type, interrupt_reason,
                referrer, tab_url, mime_type)
             VALUES (7, 'C:\\Users\\me\\Downloads\\tool.zip', 'C:\\Users\\me\\Downloads\\tool.zip',
                13300000015000000, 13300000016000000, 2048, 2048, 1, 0, 0,
                'https://example.com/path?q=keyword', 'https://example.com/downloads',
                'application/zip')",
            [],
        )?;
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://example.com/path?q=keyword', 'Example Page', 3, 1, 13300000020000000, 0)",
            [],
        )?;
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (2, 'https://docs.example.test/', 'Docs', 1, 0, 13300000010000000, 0)",
            [],
        )?;
        conn.execute(
            "INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (10, 1, 13300000020000000, 0, 1, 0, 1200000)",
            [],
        )?;
        conn.execute(
            "INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (9, 2, 13300000010000000, 0, 0, 0, 0)",
            [],
        )?;
        let profile_dir = history_path
            .parent()
            .context("test history path should have parent")?;
        fs::write(
            profile_dir.join("Bookmarks"),
            serde_json::json!({
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "name": "Bookmarks Bar",
                        "children": [
                            {
                                "type": "url",
                                "name": "Example Bookmark",
                                "url": "https://example.com/bookmark",
                                "guid": "bookmark-guid-1",
                                "date_added": "13300000030000000"
                            },
                            {
                                "type": "folder",
                                "name": "Research",
                                "children": [
                                    {
                                        "type": "url",
                                        "name": "Reference Bookmark",
                                        "url": "https://research.example.test/",
                                        "guid": "bookmark-guid-2",
                                        "date_added": "13300000040000000"
                                    }
                                ]
                            }
                        ]
                    },
                    "other": {
                        "type": "folder",
                        "name": "Other Bookmarks",
                        "children": []
                    }
                }
            })
            .to_string(),
        )?;
        fs::write(
            profile_dir.join("Preferences"),
            serde_json::json!({
                "profile": {
                    "name": "Default",
                    "avatar_index": 1,
                    "created_by_version": "126.0",
                    "password_manager_enabled": true
                },
                "session": {
                    "restore_on_startup": 4,
                    "startup_urls": ["https://example.com/start"]
                },
                "homepage": "https://example.com/home",
                "homepage_is_newtabpage": false,
                "download": {
                    "default_directory": "C:\\Users\\Examiner\\Downloads",
                    "prompt_for_download": false
                },
                "default_search_provider_data": {
                    "template_url_data": {
                        "short_name": "Search",
                        "keyword": "search.example",
                        "url": "https://search.example/?q={searchTerms}"
                    }
                },
                "safebrowsing": {
                    "enabled": true
                },
                "credentials_enable_service": true,
                "autofill": {
                    "enabled": true
                },
                "extensions": {
                    "settings": {
                        "abc": { "manifest": { "name": "Test Extension" } }
                    }
                }
            })
            .to_string(),
        )?;
        Ok(())
    }

    fn create_test_chromium_history_with_pending_wal(history_path: &Path) -> Result<Connection> {
        let conn = Connection::open(history_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE urls(
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL,
                typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER DEFAULT 0 NOT NULL
             );
             CREATE TABLE visits(
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER DEFAULT 0 NOT NULL,
                segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0 NOT NULL
             );
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://wal.example/recent', 'Recent WAL Page', 1, 0, 13300000050000000, 0);
             INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (11, 1, 13300000050000000, 0, 1, 0, 0);",
        )?;
        Ok(conn)
    }

    fn create_test_firefox_profile(profile_dir: &Path) -> Result<()> {
        let places_path = profile_dir.join("places.sqlite");
        let conn = Connection::open(&places_path)?;
        conn.execute_batch(
            "CREATE TABLE moz_places(
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER,
                typed INTEGER,
                last_visit_date INTEGER,
                frecency INTEGER
             );
             CREATE TABLE moz_historyvisits(
                id INTEGER PRIMARY KEY,
                place_id INTEGER NOT NULL,
                visit_date INTEGER,
                visit_type INTEGER
             );
             CREATE TABLE moz_bookmarks(
                id INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                fk INTEGER,
                parent INTEGER,
                title TEXT,
                dateAdded INTEGER,
                lastModified INTEGER
             );",
        )?;
        let base = 1_260_489_600_000_000_i64;
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, typed, last_visit_date, frecency)
             VALUES (1, 'https://example.org/firefox?q=keyword', 'Firefox Example', 4, 1, ?1, 99)",
            params![base],
        )?;
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, typed, last_visit_date, frecency)
             VALUES (2, 'https://mozilla.example/docs', 'Mozilla Docs', 2, 0, ?1, 50)",
            params![base - 1_000_000],
        )?;
        conn.execute(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date, visit_type)
             VALUES (10, 1, ?1, 2)",
            params![base],
        )?;
        conn.execute(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date, visit_type)
             VALUES (9, 2, ?1, 1)",
            params![base - 1_000_000],
        )?;
        conn.execute(
            "INSERT INTO moz_bookmarks(id, type, fk, parent, title, dateAdded, lastModified)
             VALUES (100, 2, NULL, NULL, 'Bookmarks Menu', ?1, ?1)",
            params![base - 3_000_000],
        )?;
        conn.execute(
            "INSERT INTO moz_bookmarks(id, type, fk, parent, title, dateAdded, lastModified)
             VALUES (101, 1, 1, 100, 'Firefox Bookmark', ?1, ?1)",
            params![base - 2_000_000],
        )?;
        conn.execute(
            "INSERT INTO moz_bookmarks(id, type, fk, parent, title, dateAdded, lastModified)
             VALUES (102, 1, 2, 100, 'Docs Bookmark', ?1, ?1)",
            params![base - 1_000_000],
        )?;

        let form_conn = Connection::open(profile_dir.join("formhistory.sqlite"))?;
        form_conn.execute_batch(
            "CREATE TABLE moz_formhistory(
                id INTEGER PRIMARY KEY,
                fieldname TEXT NOT NULL,
                value TEXT NOT NULL,
                timesUsed INTEGER,
                firstUsed INTEGER,
                lastUsed INTEGER
             );",
        )?;
        form_conn.execute(
            "INSERT INTO moz_formhistory(id, fieldname, value, timesUsed, firstUsed, lastUsed)
             VALUES (1, 'searchbar-history', 'keyword', 3, ?1, ?2)",
            params![base - 5_000_000, base - 4_000_000],
        )?;

        let cookie_conn = Connection::open(profile_dir.join("cookies.sqlite"))?;
        cookie_conn.execute_batch(
            "CREATE TABLE moz_cookies(
                id INTEGER PRIMARY KEY,
                host TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT,
                path TEXT,
                expiry INTEGER,
                lastAccessed INTEGER,
                creationTime INTEGER,
                isSecure INTEGER,
                isHttpOnly INTEGER
             );",
        )?;
        cookie_conn.execute(
            "INSERT INTO moz_cookies(id, host, name, value, path, expiry, lastAccessed,
                creationTime, isSecure, isHttpOnly)
             VALUES (1, '.example.org', 'sid', 'cookie-secret', '/', 1260493200, ?1, ?2, 1, 1)",
            params![base - 2_000_000, base - 3_000_000],
        )?;

        fs::write(
            profile_dir.join("logins.json"),
            serde_json::json!({
                "logins": [{
                    "id": 1,
                    "hostname": "https://example.org",
                    "httpRealm": "Members",
                    "encryptedUsername": "encrypted-user",
                    "encryptedPassword": "encrypted-pass",
                    "timeCreated": 1260489600000_i64,
                    "timeLastUsed": 1260493200000_i64,
                    "timePasswordChanged": 1260496800000_i64,
                    "timesUsed": 2
                }]
            })
            .to_string(),
        )?;
        Ok(())
    }

    fn create_test_empty_firefox_places(profile_dir: &Path) -> Result<()> {
        fs::create_dir_all(profile_dir)?;
        Connection::open(profile_dir.join("places.sqlite"))?.execute_batch(
            "CREATE TABLE moz_places(
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    title TEXT,
                    visit_count INTEGER,
                    typed INTEGER,
                    last_visit_date INTEGER,
                    frecency INTEGER
                 );
                 CREATE TABLE moz_historyvisits(
                    id INTEGER PRIMARY KEY,
                    place_id INTEGER NOT NULL,
                    visit_date INTEGER,
                    visit_type INTEGER
                 );",
        )?;
        Ok(())
    }

    fn create_test_firefox3_downloads(downloads_path: &Path, include_row: bool) -> Result<()> {
        let conn = Connection::open(downloads_path)?;
        conn.execute_batch(
            "CREATE TABLE moz_downloads(
                id INTEGER PRIMARY KEY,
                name TEXT,
                source TEXT,
                target TEXT,
                tempPath TEXT,
                startTime INTEGER,
                endTime INTEGER,
                state INTEGER,
                referrer TEXT,
                entityID TEXT,
                currBytes INTEGER,
                maxBytes INTEGER,
                mimeType TEXT,
                preferredApplication TEXT,
                preferredAction INTEGER,
                autoResume INTEGER
             );",
        )?;
        if include_row {
            conn.execute_batch(
                "INSERT INTO moz_downloads(
                    id, name, source, target, tempPath, startTime, endTime, state,
                    referrer, entityID, currBytes, maxBytes, mimeType,
                    preferredApplication, preferredAction, autoResume
                 ) VALUES (
                    1,
                    'install_flash_player.exe',
                    'http://fpdownload.macromedia.com/get/flashplayer/current/install_flash_player.exe',
                    'file:///C:/Documents%20and%20Settings/Administrator/Desktop/install_flash_player.exe',
                    '',
                    1210744064453125,
                    1210744066203125,
                    1,
                    'http://www.adobe.com/shockwave/download/download.cgi?P1_Prod_Version=ShockwaveFlash',
                    NULL,
                    1495112,
                    1495112,
                    'application/octet-stream',
                    NULL,
                    0,
                    0
                 );",
            )?;
        }
        Ok(())
    }

    fn create_test_safari_history(history_path: &Path) -> Result<()> {
        let conn = Connection::open(history_path)?;
        conn.execute_batch(
            "CREATE TABLE history_items(
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                visit_count INTEGER,
                domain_expansion TEXT
             );
             CREATE TABLE history_visits(
                id INTEGER PRIMARY KEY,
                history_item INTEGER NOT NULL,
                visit_time REAL,
                title TEXT
             );",
        )?;
        let safari_2009_12_11 = 1_260_489_600_f64 - 978_307_200_f64;
        conn.execute(
            "INSERT INTO history_items(id, url, visit_count, domain_expansion)
             VALUES (1, 'https://apple.example/history', 3, 'apple.example')",
            [],
        )?;
        conn.execute(
            "INSERT INTO history_items(id, url, visit_count, domain_expansion)
             VALUES (2, 'https://webkit.example/docs', 1, 'webkit.example')",
            [],
        )?;
        conn.execute(
            "INSERT INTO history_visits(id, history_item, visit_time, title)
             VALUES (10, 1, ?1, 'Safari Example')",
            params![safari_2009_12_11],
        )?;
        conn.execute(
            "INSERT INTO history_visits(id, history_item, visit_time, title)
             VALUES (9, 2, ?1, 'WebKit Docs')",
            params![safari_2009_12_11 - 60.0],
        )?;
        Ok(())
    }

    fn create_test_mbr_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_mbr_image_bytes())?;
        Ok(())
    }

    fn create_test_fat_mbr_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_fat_mbr_image_bytes()?)?;
        Ok(())
    }

    fn create_test_whole_fat_image(image_path: &Path) -> Result<()> {
        fs::write(image_path, test_fat_volume_bytes()?)?;
        Ok(())
    }

    fn optional_ntfs_testfs1_path() -> Option<PathBuf> {
        let mut source_roots = Vec::new();
        if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
            source_roots.push(PathBuf::from(cargo_home).join("registry").join("src"));
        }
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            source_roots.push(
                PathBuf::from(user_profile)
                    .join(".cargo")
                    .join("registry")
                    .join("src"),
            );
        }
        if let Some(home) = std::env::var_os("HOME") {
            source_roots.push(
                PathBuf::from(home)
                    .join(".cargo")
                    .join("registry")
                    .join("src"),
            );
        }

        for source_root in source_roots {
            let Ok(registry_dirs) = fs::read_dir(source_root) else {
                continue;
            };
            for registry_dir in registry_dirs.flatten() {
                let candidate = registry_dir
                    .path()
                    .join("ntfs-0.4.0")
                    .join("testdata")
                    .join("testfs1");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn create_test_fixed_vhd_image(image_path: &Path) -> Result<()> {
        fs::write(
            image_path,
            fixed_vhd_from_disk_bytes(test_mbr_image_bytes()),
        )?;
        Ok(())
    }

    fn create_test_fat_fixed_vhd_image(image_path: &Path) -> Result<()> {
        fs::write(
            image_path,
            fixed_vhd_from_disk_bytes(test_fat_mbr_image_bytes()?),
        )?;
        Ok(())
    }

    fn test_mbr_image_bytes() -> Vec<u8> {
        let mut image = vec![0_u8; 4 * 1024 * 1024];
        let entry_offset = 446;
        image[entry_offset] = 0x00;
        image[entry_offset + 4] = 0x07;
        image[entry_offset + 8..entry_offset + 12].copy_from_slice(&2048_u32.to_le_bytes());
        image[entry_offset + 12..entry_offset + 16].copy_from_slice(&2048_u32.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;
        image
    }

    fn test_fat_mbr_image_bytes() -> Result<Vec<u8>> {
        const PARTITION_START_SECTOR: u32 = 2048;
        const SECTOR_SIZE: usize = 512;
        let fat_volume = test_fat_volume_bytes()?;
        let start = PARTITION_START_SECTOR as usize * SECTOR_SIZE;
        let sectors = u32::try_from(fat_volume.len() / SECTOR_SIZE)
            .context("test FAT volume sector count exceeds u32")?;
        let mut image = vec![0_u8; start + fat_volume.len() + SECTOR_SIZE];
        let entry_offset = 446;
        image[entry_offset] = 0x00;
        image[entry_offset + 4] = 0x01;
        image[entry_offset + 8..entry_offset + 12]
            .copy_from_slice(&PARTITION_START_SECTOR.to_le_bytes());
        image[entry_offset + 12..entry_offset + 16].copy_from_slice(&sectors.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;
        image[start..start + fat_volume.len()].copy_from_slice(&fat_volume);
        Ok(image)
    }

    fn test_fat_volume_bytes() -> Result<Vec<u8>> {
        let mut fat_cursor = io::Cursor::new(vec![0_u8; 1024 * 1024]);
        fatfs::format_volume(&mut fat_cursor, fatfs::FormatVolumeOptions::new())
            .context("formatting test FAT volume")?;
        fat_cursor.seek(SeekFrom::Start(0))?;
        {
            let fs = fatfs::FileSystem::new(&mut fat_cursor, fatfs::FsOptions::new())
                .context("opening test FAT volume")?;
            let root = fs.root_dir();
            let dfir = root
                .create_dir("DFIR")
                .context("creating test FAT directory")?;
            let mut note = dfir
                .create_file("note.txt")
                .context("creating test FAT file")?;
            note.write_all(b"FAT evidence artifact")
                .context("writing test FAT file")?;
            let case_files = root
                .create_dir("Case Files")
                .context("creating test FAT directory with spaces")?;
            let mut spaced = case_files
                .create_file("note (1).txt")
                .context("creating test FAT file with sanitized name")?;
            spaced
                .write_all(b"FAT spaced artifact")
                .context("writing test FAT file with sanitized name")?;
            let mut exact_spaced = root
                .create_file("Nitroba work.odt")
                .context("creating FAT exact-path oracle with a space")?;
            exact_spaced
                .write_all(b"known spaced ODT payload")
                .context("writing FAT exact-path oracle with a space")?;
            let mut exact_underscore = root
                .create_file("Nitroba_work.odt")
                .context("creating FAT exact-path collision oracle")?;
            exact_underscore
                .write_all(b"known underscore ODT payload")
                .context("writing FAT exact-path collision oracle")?;
        }
        Ok(fat_cursor.into_inner())
    }

    fn fixed_vhd_from_disk_bytes(mut image: Vec<u8>) -> Vec<u8> {
        let disk_size = image.len() as u64;
        let mut footer = [0_u8; 512];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2_u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        footer[28..32].copy_from_slice(b"kdft");
        footer[32..36].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&disk_size.to_be_bytes());
        footer[48..56].copy_from_slice(&disk_size.to_be_bytes());
        footer[56..60].copy_from_slice(&512_u32.to_be_bytes());
        footer[60..64].copy_from_slice(&2_u32.to_be_bytes());
        let checksum = !footer
            .iter()
            .fold(0_u32, |acc, byte| acc.wrapping_add(u32::from(*byte)));
        footer[64..68].copy_from_slice(&checksum.to_be_bytes());
        image.extend_from_slice(&footer);
        image
    }

    fn unique_case_path(label: &str) -> PathBuf {
        unique_temp_dir("case-parent").join(format!("kdft-{label}.sqlite"))
    }

    fn cleanup_case_path(case_path: &Path) {
        let parent = case_path.parent().map(Path::to_path_buf);
        let _ = fs::remove_file(case_path);
        if let Some(parent) = parent {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos();
        path.push(format!("kdft-v1-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create test temp directory");
        path
    }

    fn path_str(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
