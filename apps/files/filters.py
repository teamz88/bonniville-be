import django_filters
from django.db.models import Q
from .models import File, FileCategory, FileStatus


class FileFilter(django_filters.FilterSet):
    """Filter for file listing"""
    
    # Category filter
    category = django_filters.ChoiceFilter(
        choices=FileCategory.choices,
        field_name='category'
    )
    
    # Status filter
    status = django_filters.ChoiceFilter(
        choices=FileStatus.choices,
        field_name='status'
    )
    
    # File type filter
    file_type = django_filters.CharFilter(
        field_name='file_type',
        lookup_expr='icontains'
    )
    
    # File extension filter
    extension = django_filters.CharFilter(
        field_name='file_extension',
        lookup_expr='iexact'
    )
    
    # Size filters
    min_size = django_filters.NumberFilter(
        field_name='file_size',
        lookup_expr='gte'
    )
    max_size = django_filters.NumberFilter(
        field_name='file_size',
        lookup_expr='lte'
    )
    
    # Date filters
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )
    
    # Boolean filters
    is_public = django_filters.BooleanFilter(
        field_name='is_public'
    )
    is_shared = django_filters.BooleanFilter(
        field_name='is_shared'
    )
    
    # Owner filter (admin only)
    owner = django_filters.CharFilter(
        method='filter_by_owner'
    )
    
    # Tag filter
    tags = django_filters.CharFilter(
        method='filter_by_tags'
    )
    
    # Folder filter
    folder = django_filters.UUIDFilter(
        field_name='folder_id'
    )
    
    # Note: Removed custom search filter to avoid conflict with DRF SearchFilter
    
    class Meta:
        model = File
        fields = [
            'category', 'status', 'file_type', 'extension',
            'min_size', 'max_size', 'created_after', 'created_before',
            'is_public', 'is_shared', 'owner', 'tags', 'folder'
        ]
    
    def filter_by_owner(self, queryset, name, value):
        """Filter by file owner username or email"""
        return queryset.filter(
            Q(user__username__icontains=value) |
            Q(user__email__icontains=value)
        )
    
    def filter_by_tags(self, queryset, name, value):
        """Filter by tags (comma-separated)"""
        if not value:
            return queryset
        
        tags = [tag.strip().lower() for tag in value.split(',')]
        query = Q()
        
        for tag in tags:
            query |= Q(tags__icontains=tag)
        
        return queryset.filter(query)
    
    # filter_search method removed - using DRF SearchFilter instead