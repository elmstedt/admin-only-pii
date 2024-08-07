# frozen_string_literal: true

# name: admin-only-pii
# about: Enhances privacy by hiding personally identifiable information from non-admin users
# version: 0.99.2
# authors: Jake Elmstedt
# url: https://github.com/elmstedt/admin-only-pii

AFFECTED_SERIALIZERS = %i[AdminUserSerializer AdminUserListSerializer UserAuthTokenSerializer UserCardSerializer].freeze
PII_FIELDS = %w[ip_address registration_ip_address client_ip location email secondary_emails].freeze
HIDDEN_REPORTS = %w[suspicious_logins].freeze

# AdminOnlyPII module handles PII-related operations
module AdminOnlyPII
  module_function

  def can_see_pii?(user)
    user.admin?
  end

  def remove_pii(hash, user, serializer)
    return hash if can_see_pii?(user)

    hash.each_with_object({}) do |(key, value), result|
      result[key] = if PII_FIELDS.include?(key.to_s)
                      serializer.respond_to?(key) ? sanitize_pii(serializer.public_send(key)) : next
                    elsif value.is_a?(Hash)
                      remove_pii(value, user, serializer)
                    else
                      value
                    end
    end
  end

  def sanitize_pii(value)
    case value
    when String then I18n.t('staff_action_logs.unknown')
    when Numeric then 0
    when TrueClass, FalseClass then false
    end
  end
end

after_initialize do
  SiteSetting.moderators_view_emails = false
  SiteSetting.dashboard_hidden_reports = HIDDEN_REPORTS.join('|')

  AFFECTED_SERIALIZERS.each do |serializer_name|
    serializer_name.to_s.constantize.class_eval do
      alias_method :original_attributes, :attributes
      def attributes(*args)
        AdminOnlyPII.remove_pii(original_attributes(*args), scope.user, self)
      end

      PII_FIELDS.each do |field|
        next unless method_defined?(field)

        alias_method :"original_#{field}", field
        define_method(field) do
          if AdminOnlyPII.can_see_pii?(scope.user)
            public_send(:"original_#{field}")
          else
            AdminOnlyPII.sanitize_pii(public_send(:"original_#{field}"))
          end
        end
      end
    end
  end

  add_to_serializer(:current_user, :can_see_pii) do
    AdminOnlyPII.can_see_pii?(object)
  end
end
